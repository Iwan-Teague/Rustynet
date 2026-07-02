//! DeepSeek MCP Server — calls the DeepSeek API as a first-class sub-agent tool.
//!
//! Explicit DeepSeek + live-lab tools so the calling agent can choose the right
//! level of access:
//!
//! - `deepseek_read`       — analysis/research only (explain, assess, review)
//! - `deepseek_write`      — generation only (code, docs, config, tests)
//! - `deepseek_read_write` — full autonomy: analyze existing content then generate output
//! - `deepseek_agent` — READ-ONLY autonomous research agent: DeepSeek drives an
//!   OpenAI-style tool-calling loop against a confined, read-only tool set
//!   (read_file/list_dir/grep/git/find_files/find_definition/utm_vm_status/
//!   lab_node_reachable/host_system_info/host_disk_status/lab_run_status/
//!   lab_run_detail/lab_loop_journal/lab_inventory/lab_jobs/lab_guest_exec/
//!   lab_job_log/lab_stage_log/lab_report_grep/lab_report_artifacts) that
//!   inspects the LOCAL Rustynet repo + UTM lab. It cannot write.
//! - `deepseek_lab_run` — deterministic live-lab launch + auto-triage on fail.
//! - `deepseek_next_live_lab_target` — read-only next target chooser from the run matrix.
//! - `deepseek_autonomous_live_lab_loop` — reconcile stale jobs, choose target, launch.
//! - `deepseek_recover_lab_environment` — async stop-after-ready recovery pass.
//! - `deepseek_reconcile_jobs` — repair stale labrun records after interruption.
//! - `deepseek_doc_sync` — PROPOSE-ONLY, READ-ONLY docs-sync: after a
//!   lab-verified fix, a grounded agent (same loop, but the repo-reads-only tool
//!   subset — NO lab/guest/cargo tools) reads the current docs and proposes the
//!   exact docs-only edits (file/old_string/new_string/rationale) to keep them in
//!   sync. It writes nothing; a human applies the edits. Async — poll
//!   `deepseek_live_lab_result` for the structured proposal.
//!
//! Model selection per call:
//! - `"flash"` → deepseek-v4-flash (fast, low cost — default)
//! - `"pro"`   → deepseek-v4-pro (deep chain-of-thought at max reasoning effort, slower)
//!
//! API key resolution order:
//! 1. DEEPSEEK_API_KEY env var
//! 2. ~/Desktop/deepseek_api.md
//! 3. ~/.deepseek_api_key

#![forbid(unsafe_code)]

use rustynet_mcp::{
    McpServer, ServerInfo, Tool, ToolCallResult, json_schema_boolean, json_schema_object,
    json_schema_string, repo_root, run_server, run_with_timeout, spawn_logged, tail_file,
    text_content, tool_error, truncate_output,
};
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Parsed run-matrix CSV: (header, rows).
type RunMatrixRows = (Vec<String>, Vec<Vec<String>>);

const FLASH_MODEL: &str = "deepseek-v4-flash";
const PRO_MODEL: &str = "deepseek-v4-pro";
const API_URL: &str = "https://api.deepseek.com/chat/completions";
const REQUEST_TIMEOUT_SECS: u64 = 180;

/// Hard cap on bytes returned from any single agent tool result, so one tool
/// call (e.g. a huge file or grep dump) can never blow up the model's context
/// or the MCP response. The model still gets a truncation note.
const TOOL_RESULT_MAX_BYTES: usize = 16 * 1024;
/// Default / hard-max bytes for `read_file`.
const READ_FILE_DEFAULT_BYTES: usize = 64 * 1024;
const READ_FILE_HARD_MAX_BYTES: usize = 256 * 1024;
/// Default agent step budget and its hard cap.
const AGENT_DEFAULT_MAX_STEPS: u64 = 12;
const AGENT_HARD_MAX_STEPS: u64 = 20;
/// Timeout for any local subprocess the agent tools spawn (grep/git/uname/utmctl).
const SUBPROC_TIMEOUT_SECS: u64 = 30;
/// Wall-clock cap for a full live-lab orchestration launched by deepseek_lab_run.
/// Generous (90 min) — a 3-OS pass + diagnose can run long; the worker thread
/// blocks on it while the MCP call already returned a job_id.
const LAB_ORCHESTRATOR_TIMEOUT_SECS: u64 = 5400;
/// Concurrency cap for opt-in parallel lab runs (e.g. the macOS↔Windows pipeline
/// on disjoint guests). Default is still a singleton (1) unless `allow_concurrent`.
const MAX_CONCURRENT_LAB_RUNS: usize = 3;
/// A deepseek_lab_run worker records the orchestrator pid within ~1s of spawning
/// it (`record_orchestrator_pid` runs immediately after the non-blocking spawn).
/// A `state=running` record with NO pid recorded and no completion artifact that
/// is older than this is therefore a phantom — the worker died BEFORE the spawn
/// (e.g. a stdio driver disconnected right after the async ack, killing the
/// server before its worker thread launched the detached orchestrator). Such a
/// record can never be repaired by the pid-liveness path, so it would peg the
/// singleton gate forever. Reclassify it crashed once this much time has passed.
/// Keep this above the expected spawn window, but short enough that a direct
/// stdio driver that exits after the async ack cannot block the lab for minutes.
const RECONCILE_NO_PID_STALE_SECS: u64 = 30;
/// Standard lab SSH material + inventory (mirrors the lab-state MCP defaults).
const LAB_SSH_IDENTITY_REL: &str = ".ssh/rustynet_lab_ed25519";
const LAB_KNOWN_HOSTS_REL: &str = ".ssh/known_hosts";
/// Timeout for the agents' `cargo check`/`cargo test` grounding tools. Generous —
/// a cold cross-target check can run minutes; the step budget caps how many run.
const CARGO_TOOL_TIMEOUT_SECS: u64 = 420;
/// Timeout for a single SSH guest-diagnostic round trip (connect + one command).
const GUEST_SSH_TIMEOUT_SECS: u64 = 45;
/// Where THIS server's async-job records are persisted (repo-relative; under
/// gitignored state/). Distinct from `JOBS_SUBDIR` (`state/mcp-jobs`, which is
/// the LAB-STATE MCP's job dir the grounding agent reads via `lab_job_log`).
/// Mirrors the lab-state pattern so a deepseek job survives an MCP-server reload:
/// the in-memory map is the fast path, this dir is the durable record
/// `deepseek_live_lab_result` falls back to.
const DEEPSEEK_JOBS_SUBDIR: &str = "state/deepseek-mcp-jobs";
/// Completion artifact the orchestrator writes inside a run's report dir. Its
/// presence after a reload proves the orphaned orchestrator finished even though
/// the in-memory worker that was waiting on it died.
const ORCHESTRATE_RESULT_REL: &str = "orchestration/orchestrate_result.json";

/// State of an async triage job: still running (with its start time, for elapsed
/// reporting) or finished with its assembled report.
enum TriageJob {
    Running { started: Instant },
    Done(String),
}

type JobMap = Arc<Mutex<HashMap<String, TriageJob>>>;

/// One record's outcome from `deepseek_reconcile_jobs`: which record changed, the
/// transition, and why. Collected per reconciled record for the summary report.
struct ReconcileChange {
    job_id: String,
    kind: String,
    old_state: String,
    new_state: String,
    reason: String,
}

/// One deterministic live-lab target selected from the run matrix or an explicit
/// operator key. The `args` object is fed directly to `deepseek_lab_run`.
#[derive(Clone)]
struct LiveLabTarget {
    key: String,
    area: String,
    reason: String,
    args: Value,
}

/// Which confined, read-only tool repertoire a grounded agent run is allowed to
/// use. Both variants are READ-ONLY (no tool mutates the repo, the lab, or any
/// guest); the variant only restricts WHICH read-only tools are exposed.
#[derive(Clone, Copy)]
enum AgentToolset {
    /// The full grounding repertoire: repo reads + read-only git + live-lab/guest
    /// diagnostics + cargo grounding. Used by deepseek_agent and the triage
    /// pipeline, which need to inspect real lab/run state.
    Full,
    /// REPO-READS-ONLY subset: read_file / list_dir / grep / find_files /
    /// find_definition / find_references / read-only git. No lab, guest, host,
    /// or cargo tools. Used by deepseek_doc_sync so a docs-sync proposal can only
    /// read repo files — it can touch no lab/guest surface at all.
    DocsRepoReadOnly,
}

impl AgentToolset {
    /// The OpenAI-style tool-definition array advertised to the model for this
    /// toolset. `DocsRepoReadOnly` is the filtered repo-reads-only subset.
    fn definitions(self) -> Value {
        match self {
            AgentToolset::Full => agent_tool_definitions(),
            AgentToolset::DocsRepoReadOnly => doc_sync_tool_definitions(),
        }
    }

    /// Whether a tool name is permitted under this toolset. The dispatch path
    /// gates on this so that even if the model emits a tool name outside the
    /// advertised set, a disallowed (e.g. lab/guest/cargo) tool is rejected
    /// rather than executed.
    fn allows(self, name: &str) -> bool {
        match self {
            AgentToolset::Full => true,
            AgentToolset::DocsRepoReadOnly => DOC_SYNC_TOOL_NAMES.contains(&name),
        }
    }
}

/// The exact repo-reads-only tool names doc_sync may call. Kept in lockstep with
/// `doc_sync_tool_definitions()`; the dispatch gate (`AgentToolset::allows`)
/// rejects anything not in this list, so no lab/guest/host/cargo tool is
/// reachable from a docs-sync run.
const DOC_SYNC_TOOL_NAMES: &[&str] = &[
    "read_file",
    "list_dir",
    "grep",
    "git",
    "find_files",
    "find_definition",
    "find_references",
];

#[derive(Clone)]
struct DeepSeekServer {
    api_key: String,
    agent: ureq::Agent,
    repo_root: PathBuf,
    /// Async triage jobs keyed by job id. Shared (Arc) so a clone handed to a
    /// worker thread mutates the same map the poll tool reads. This is the fast
    /// path only — every job is ALSO persisted under [`DEEPSEEK_JOBS_SUBDIR`] so it
    /// survives an MCP-server reload (the in-memory map is wiped on restart).
    jobs: JobMap,
    /// Per-process monotonic sequence for the trailing token of a job id. NOT
    /// the whole id: ids embed a wall-clock millis + the pid (see [`new_job_id`])
    /// so they neither collide nor become unfindable across server restarts —
    /// the bare counter used to reset to 1 every start, colliding ids and
    /// reusing report dirs across reloads.
    job_seq: Arc<AtomicU64>,
}

impl DeepSeekServer {
    fn new() -> Self {
        let api_key = load_api_key().unwrap_or_else(|e| {
            eprintln!("DeepSeek MCP: {e}");
            String::new()
        });
        let agent = ureq::AgentBuilder::new()
            .timeout_read(Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .timeout_write(Duration::from_secs(30))
            .build();
        Self {
            api_key,
            agent,
            repo_root: repo_root(),
            jobs: Arc::new(Mutex::new(HashMap::new())),
            job_seq: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Build a unique, reload-stable async-job id with the given prefix
    /// (`labrun` / `triage` / `docsync` — the prefix MUST remain the first token
    /// because drive_deepseek.py's JOB_RE and the `lab_run_status` filter key on
    /// it). The id embeds a wall-clock millis + the pid + a per-process sequence,
    /// mirroring the lab-state MCP's `ll-{millis}-{pid}-{seq}` scheme: each piped
    /// client request is a fresh server process whose `job_seq` restarts at 0, so
    /// without the pid + millis two same-process-lifetime ids would collide and
    /// silently overwrite each other's persisted record.
    fn new_job_id(&self, prefix: &str) -> String {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let seq = self.job_seq.fetch_add(1, Ordering::Relaxed);
        format!("{prefix}-{millis}-{}-{seq}", std::process::id())
    }

    /// Directory where THIS server's async-job records are persisted
    /// (repo-relative under gitignored state/). Mirrors lab-state's `jobs_dir`.
    fn jobs_dir(&self) -> PathBuf {
        self.repo_root.join(DEEPSEEK_JOBS_SUBDIR)
    }

    /// Per-job record path: `<DEEPSEEK_JOBS_SUBDIR>/<job_id>.json`.
    fn job_record_path(&self, job_id: &str) -> PathBuf {
        self.jobs_dir().join(format!("{job_id}.json"))
    }

    /// Persist a job record durably (so a reloaded server can still find it).
    /// Written atomically-ish — to a sibling `.tmp` then renamed — so a
    /// concurrent poll never reads a half-written record. Best-effort: a write
    /// failure is logged, not fatal (the in-memory map remains the fast path).
    fn write_job_record(&self, job_id: &str, rec: &Value) {
        let dir = self.jobs_dir();
        if let Err(e) = std::fs::create_dir_all(&dir) {
            eprintln!(
                "DeepSeek MCP: cannot create jobs dir {}: {e}",
                dir.display()
            );
            return;
        }
        let final_path = self.job_record_path(job_id);
        let tmp_path = dir.join(format!("{job_id}.json.tmp"));
        let body = serde_json::to_string_pretty(rec).unwrap_or_default();
        if let Err(e) = std::fs::write(&tmp_path, body) {
            eprintln!("DeepSeek MCP: cannot write job record tmp: {e}");
            return;
        }
        if let Err(e) = std::fs::rename(&tmp_path, &final_path) {
            eprintln!("DeepSeek MCP: cannot finalize job record: {e}");
            let _ = std::fs::remove_file(&tmp_path);
        }
    }

    /// Read a persisted job record back (the reload-survival fallback path).
    fn read_job_record(&self, job_id: &str) -> Option<Value> {
        let s = std::fs::read_to_string(self.job_record_path(job_id)).ok()?;
        serde_json::from_str(&s).ok()
    }

    /// Mark a job DONE both in memory (fast path) and on disk (reload-survival).
    /// Reads the existing record so static fields (area, report_dir, started_unix)
    /// are preserved; if no record exists (legacy / write failed) it writes a
    /// minimal one so the report is still recoverable.
    fn finish_job(&self, job_id: &str, report: String) {
        if let Ok(mut jobs) = self.jobs.lock() {
            jobs.insert(job_id.to_string(), TriageJob::Done(report.clone()));
        }
        let mut rec = self
            .read_job_record(job_id)
            .unwrap_or_else(|| json!({ "job_id": job_id, "started_unix": now_unix() }));
        if let Some(obj) = rec.as_object_mut() {
            obj.insert("state".into(), json!("done"));
            obj.insert("report_text".into(), json!(report));
            obj.insert("finished_unix".into(), json!(now_unix()));
        }
        self.write_job_record(job_id, &rec);
    }

    /// Stamp the running job record with the detached orchestrator's pid, merging
    /// into the existing record so the static creation fields (area, report_dir,
    /// started_unix) survive. Best-effort: a missing record (write failed at
    /// creation) is recreated minimally so the pid is still recorded. This is what
    /// lets a crashed/killed run (dead pid, no completion artifact) be recognised
    /// instead of pegging the singleton slot forever.
    fn record_orchestrator_pid(&self, job_id: &str, pid: u32) {
        let mut rec = self
            .read_job_record(job_id)
            .unwrap_or_else(|| json!({ "job_id": job_id, "started_unix": now_unix() }));
        if let Some(obj) = rec.as_object_mut() {
            obj.insert("orchestrator_pid".into(), json!(pid));
        }
        self.write_job_record(job_id, &rec);
    }

    /// Read the orchestrator pid recorded for a job (None for old records written
    /// before the field existed, or before the child was spawned). Used by the
    /// in-flight self-heal filter and the reconcile tool to probe liveness.
    fn job_orchestrator_pid(rec: &Value) -> Option<u32> {
        rec.get("orchestrator_pid")
            .and_then(|v| v.as_u64())
            .and_then(|n| u32::try_from(n).ok())
    }

    /// True when a record has NO orchestrator pid recorded and is older than
    /// [`RECONCILE_NO_PID_STALE_SECS`] — i.e. the worker died before it could
    /// spawn the orchestrator and record its pid. Such a record can never be
    /// repaired by the pid-liveness path, so both the in-flight gate and the
    /// reconcile tool treat it as a crashed phantom once aged. A record with a
    /// recorded pid, or one still inside the startup window, returns false.
    /// Missing/zero `started_unix` returns false (cannot age it — stay safe).
    fn record_no_pid_stale(rec: &Value) -> bool {
        if Self::job_orchestrator_pid(rec).is_some() {
            return false;
        }
        let started = rec
            .get("started_unix")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        started > 0 && now_unix().saturating_sub(started) > RECONCILE_NO_PID_STALE_SECS
    }

    /// Read the orchestrator's completion artifact for a run, if it exists. After
    /// a server reload the in-memory worker is gone, but the detached orchestrator
    /// keeps running and writes `orchestration/orchestrate_result.json` when it
    /// finishes; its presence + contents let the poll path surface the OUTCOME of
    /// an orphaned run. Returns (overall_status, first_failed_stage).
    fn read_orchestrate_outcome(&self, report_dir: &str) -> Option<(String, Option<String>)> {
        let path = self.repo_root.join(report_dir).join(ORCHESTRATE_RESULT_REL);
        let body = std::fs::read_to_string(path).ok()?;
        let v: Value = serde_json::from_str(&body).ok()?;
        let overall = v
            .get("overall_status")
            .and_then(|s| s.as_str())
            .unwrap_or("unknown")
            .to_string();
        let first_failed = v
            .get("outcomes")
            .and_then(|o| o.as_array())
            .and_then(|arr| {
                arr.iter().find_map(|st| {
                    let status = st.get("status").and_then(|s| s.as_str())?;
                    if status.eq_ignore_ascii_case("fail") {
                        st.get("stage").and_then(|s| s.as_str()).map(str::to_string)
                    } else {
                        None
                    }
                })
            });
        Some((overall, first_failed))
    }

    fn call(&self, system: &str, user: &str, model: &str) -> Result<String, String> {
        let messages = json!([
            {"role": "system", "content": system},
            {"role": "user",   "content": user},
        ]);
        let parsed = self.chat(messages, None, model)?;
        let msg = &parsed["choices"][0]["message"];

        // deepseek-reasoner returns both reasoning_content and content.
        let reasoning = msg["reasoning_content"].as_str().unwrap_or("").trim();
        let content = msg["content"]
            .as_str()
            .ok_or_else(|| format!("Unexpected DeepSeek response shape: {parsed}"))?
            .trim();

        if !reasoning.is_empty() {
            Ok(format!(
                "<reasoning>\n{reasoning}\n</reasoning>\n\n{content}"
            ))
        } else {
            Ok(content.to_string())
        }
    }

    /// Single chat-completions round trip. Returns the raw parsed response JSON.
    /// `tools` is the OpenAI-style tool-definition array (DeepSeek is
    /// OpenAI-compatible); when `Some`, the request advertises the tools so the
    /// model may answer with `tool_calls`.
    fn chat(&self, messages: Value, tools: Option<&Value>, model: &str) -> Result<Value, String> {
        if self.api_key.is_empty() {
            return Err("DeepSeek API key not configured. \
                Set DEEPSEEK_API_KEY env var, or create ~/Desktop/deepseek_api.md \
                or ~/.deepseek_api_key with the key as the only content."
                .into());
        }
        let mut body = json!({
            "model": model,
            "messages": messages,
            "max_tokens": 8192,
        });
        // V4 Pro honors `reasoning_effort`; "max" is the highest level (docs:
        // high|max — max is for the hardest planning / multi-step coding agents).
        // Flash ignores it. Pro is only ever used for hard reasoning, so always
        // drive it at max.
        if model == PRO_MODEL {
            body["reasoning_effort"] = json!("max");
        }
        if let Some(tools) = tools {
            body["tools"] = tools.clone();
        }
        let response = self
            .agent
            .post(API_URL)
            .set("Authorization", &format!("Bearer {}", self.api_key))
            .set("Content-Type", "application/json")
            .send_json(body)
            .map_err(|e| format!("DeepSeek API request failed: {e}"))?;

        response
            .into_json()
            .map_err(|e| format!("DeepSeek response parse failed: {e}"))
    }

    // ── Autonomous read-only research agent ──────────────────────────────

    /// Drive the OpenAI-style tool-calling loop. The model is given the
    /// read-only tool set and a system prompt; on each step it may answer with
    /// `tool_calls` (which we execute locally and feed back) or with a final
    /// `content` answer (which we return). Bounded by `max_steps`.
    fn run_agent(&self, prompt: &str, model: &str, max_steps: u64) -> Result<String, String> {
        self.run_grounded(
            "agent",
            AGENT_SYSTEM_PROMPT,
            prompt,
            model,
            max_steps,
            AgentToolset::Full,
        )
    }

    /// The grounded read-only tool-calling loop, parameterized by system prompt
    /// AND tool set so the failure-triage roles (research / verify / review) and
    /// the docs-sync role reuse the exact same confined, read-only loop, swapping
    /// only the instructions and which read-only tools are exposed. No role can
    /// write — every tool in every set is read-only; `toolset` only narrows WHICH
    /// read-only tools are reachable (docs-sync gets repo-reads only).
    fn run_grounded(
        &self,
        label: &str,
        system: &str,
        prompt: &str,
        model: &str,
        max_steps: u64,
        toolset: AgentToolset,
    ) -> Result<String, String> {
        let tools = toolset.definitions();
        // Budget-aware system prompt: without this, flash agents tend to spend
        // EVERY step on tool calls and then, when forced to answer with no tools
        // left, emit tool-call markup instead of prose (→ an empty budget note).
        // Telling them the budget up front makes them synthesize a real conclusion
        // before they run out.
        let system_with_budget = format!(
            "{system}\n\nSTEP BUDGET: you have at most {max_steps} tool-calling steps. Investigate \
             efficiently, then write your FINAL answer as plain prose well before the budget runs \
             out — a grounded conclusion from what you have already gathered beats spending every \
             step on more tools. In a final answer, output prose ONLY: never emit tool-call or \
             function-call syntax.\n\nTOOLS — you have a rich READ-ONLY repertoire for grounding; \
             USE IT AGGRESSIVELY: read_file (with offset/max_bytes for a line range), list_dir, \
             grep (with optional `context` lines for surrounding code), find_files, find_definition \
             (where a symbol is DECLARED), find_references (where a symbol is USED — call sites / \
             impact), read-only git (log / show / diff / blame / cat-file — history and \
             'did this regress, and in which commit?'), plus the live-lab tools (lab_inventory, \
             lab_run_status, lab_run_detail, lab_stage_log, lab_report_grep, lab_report_artifacts, \
             lab_guest_exec, utm_vm_status, lab_node_reachable), AND grounding-by-EXECUTION: \
             cargo_check (does it COMPILE — host = macOS+common code, target='windows' = the \
             x86_64-pc-windows-gnu cross-target for Windows cfg code — and what is the REAL compiler \
             error?) and cargo_test (does a scoped test currently pass/fail?). Ground EVERY claim in \
             a file:line, a log line, or a check/test you actually RAN — never infer from memory. \
             When a claim is about compiling or a test outcome, RUN cargo_check / cargo_test to \
             confirm it instead of guessing; and cross-check with a second tool (grep → read_file, \
             find_definition → find_references, or git blame on the line) before asserting it."
        );
        let mut messages = json!([
            {"role": "system", "content": system_with_budget},
            {"role": "user", "content": prompt},
        ]);
        let mut trace: Vec<String> = Vec::new();
        eprintln!("[live-lab] agent '{label}' ({model}) started — step budget {max_steps}");

        for step in 1..=max_steps {
            let parsed = self.chat(messages.clone(), Some(&tools), model)?;
            let message = &parsed["choices"][0]["message"];

            let tool_calls = message.get("tool_calls").and_then(|v| v.as_array());
            match tool_calls {
                Some(calls) if !calls.is_empty() => {
                    let called: Vec<&str> = calls
                        .iter()
                        .filter_map(|c| c["function"]["name"].as_str())
                        .collect();
                    eprintln!(
                        "[live-lab] agent '{label}' step {step}/{max_steps}: {} tool call(s) -> {}",
                        called.len(),
                        called.join(", ")
                    );
                    // Append the assistant message verbatim so the tool_call_ids
                    // it references resolve against the tool replies we add next.
                    if let Some(arr) = messages.as_array_mut() {
                        arr.push(message.clone());
                    }
                    for call in calls {
                        let id = call.get("id").and_then(|v| v.as_str()).unwrap_or("");
                        let func = &call["function"];
                        let name = func.get("name").and_then(|v| v.as_str()).unwrap_or("");
                        let args_raw = func.get("arguments").and_then(|v| v.as_str()).unwrap_or("");
                        let args: Value = serde_json::from_str(args_raw).unwrap_or(Value::Null);

                        // Gate on the run's toolset so a disallowed tool (e.g. a
                        // lab/guest/cargo tool requested from a docs-sync run) is
                        // refused rather than executed — defense in depth on top
                        // of only advertising the permitted definitions.
                        let result = if toolset.allows(name) {
                            self.dispatch_agent_tool(name, &args)
                        } else {
                            format!(
                                "ERROR: tool '{name}' is not available in this run's tool set \
                                 (docs-sync is restricted to repo reads only)"
                            )
                        };
                        let bounded = truncate_output(&result, 400, TOOL_RESULT_MAX_BYTES);
                        trace.push(format!(
                            "- `{name}`({}) → {} bytes",
                            summarize_args(&args),
                            bounded.len()
                        ));
                        if let Some(arr) = messages.as_array_mut() {
                            arr.push(json!({
                                "role": "tool",
                                "tool_call_id": id,
                                "content": bounded,
                            }));
                        }
                    }
                }
                _ => {
                    // No tool calls → final answer.
                    eprintln!(
                        "[live-lab] agent '{label}' final answer at step {step} ({} tool call(s) total)",
                        trace.len()
                    );
                    let content = strip_dsml_markup(message["content"].as_str().unwrap_or(""));
                    let reasoning =
                        strip_dsml_markup(message["reasoning_content"].as_str().unwrap_or(""));
                    let content = if content.is_empty() {
                        "(the agent tried to call more tools instead of answering; the step budget \
                         is likely too low for this investigation — raise max_steps)"
                            .to_string()
                    } else {
                        content
                    };
                    let answer = if reasoning.is_empty() {
                        content
                    } else {
                        format!("<reasoning>\n{reasoning}\n</reasoning>\n\n{content}")
                    };
                    return Ok(format!(
                        "{answer}\n\n## Tools used ({} call(s) over {step} step(s))\n{}",
                        trace.len(),
                        if trace.is_empty() {
                            "_(none — answered without inspecting the repo)_".to_string()
                        } else {
                            trace.join("\n")
                        }
                    ));
                }
            }
        }

        // Step budget exhausted: ask for a best-effort answer with no more tools
        // so the loop always terminates with something useful.
        if let Some(arr) = messages.as_array_mut() {
            arr.push(json!({
                "role": "user",
                "content": "You have used all your tool-calling steps and have NO further tool access. Write your final analysis NOW as plain prose only, based on what you already gathered. Do NOT output any tool-call or function-call syntax — it will be discarded.",
            }));
        }
        let parsed = self.chat(messages, None, model)?;
        let raw = parsed["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("");
        let content = {
            let stripped = strip_dsml_markup(raw);
            if stripped.is_empty() {
                "(the agent exhausted its step budget mid-investigation and produced no final \
                 synthesis — raise max_steps for a deeper triage)"
                    .to_string()
            } else {
                stripped
            }
        };
        Ok(format!(
            "{content}\n\n## Tools used ({} call(s); step budget of {max_steps} reached)\n{}",
            trace.len(),
            if trace.is_empty() {
                "_(none)_".to_string()
            } else {
                trace.join("\n")
            }
        ))
    }

    /// Run the RIGID, non-negotiable failure-triage pipeline on a live-lab
    /// failure. The three steps ALWAYS run, in this exact order — it is
    /// deterministic server control flow, never model-chosen:
    ///
    /// 1. Flash research — why/where/what failed (+ optional fix), grounded.
    /// 2. Flash verify — scrutinize every claim against the real repo/lab.
    /// 3. v4-pro review — independently re-verify + judge the fix (max reasoning).
    ///
    /// NO code changes at any step. Every step is a read-only grounded agent;
    /// none can write the repo. The later steps receive the earlier outputs as
    /// context. Returns the assembled multi-section report for the main agent to
    /// verify and act on.
    fn run_triage(&self, failure_context: &str, max_steps: u64) -> String {
        const RESEARCH_SYSTEM: &str = "\
            You are a live-lab failure researcher for the RustyNet project. You are READ-ONLY: \
            your tools only inspect the local repo + UTM lab; you CANNOT edit, write, or run the \
            lab. Given a live-lab failure, determine WHY it failed, WHERE (exact file:line and/or \
            stage/log), and WHAT happened. Ground EVERY claim in evidence you actually read via \
            your tools (cite file:line and log excerpts) — never guess or rely on memory. You MAY \
            propose how to fix it; more grounded detail helps the human engineer. End with a \
            concise numbered claims list, each claim paired with its evidence citation.";
        const VERIFY_SYSTEM: &str = "\
            You are a skeptical verifier for the RustyNet project. You are READ-ONLY. You are given \
            a draft research report about a live-lab failure. Scrutinize EVERY claim against the \
            actual repo + lab using your tools: is the code really at the file:line it cites? did \
            that stage/log really show what is claimed? is the root cause actually supported, or \
            merely plausible? For each claim, mark it CONFIRMED (with the evidence you re-checked) \
            or REFUTED/UNSUPPORTED (with what you actually found instead). Correct any claim not \
            grounded in truth. Do not invent new fixes — your job is to make the report truthful.";
        const REVIEW_SYSTEM: &str = "\
            You are the senior reviewer for the RustyNet project. You are READ-ONLY and MUST NOT \
            change code. You are given a failure's draft research and an independent verification \
            pass. Independently re-verify the surviving claims against the actual repo + lab with \
            your tools, resolve any disagreement between the two passes, and judge whether the \
            proposed fix is actually the BEST option (or propose a better-grounded one). Produce \
            the FINAL report for the human engineer: root cause, exact location(s) (file:line), \
            the recommended fix and why it is best, your confidence, and any residual uncertainty \
            the engineer must check before changing code. You propose; the human verifies and disposes.";

        // Step 1 — Flash research (grounded, read-only).
        let research = self
            .run_grounded(
                "research",
                RESEARCH_SYSTEM,
                &format!("Live-lab failure to triage:\n\n{failure_context}"),
                FLASH_MODEL,
                max_steps,
                AgentToolset::Full,
            )
            .unwrap_or_else(|e| format!("(research step failed: {e})"));

        // Step 2 — Flash verification of the research claims (grounded, read-only).
        let verified = self
            .run_grounded(
                "verify",
                VERIFY_SYSTEM,
                &format!(
                    "Original failure context:\n\n{failure_context}\n\n\
                     ## Draft research report to scrutinize\n\n{research}"
                ),
                FLASH_MODEL,
                max_steps,
                AgentToolset::Full,
            )
            .unwrap_or_else(|e| format!("(verification step failed: {e})"));

        // Step 3 — v4-pro review at max reasoning (grounded, read-only).
        let final_review = self
            .run_grounded(
                "review",
                REVIEW_SYSTEM,
                &format!(
                    "Original failure context:\n\n{failure_context}\n\n\
                     ## Draft research\n\n{research}\n\n\
                     ## Independent verification pass\n\n{verified}"
                ),
                PRO_MODEL,
                max_steps,
                AgentToolset::Full,
            )
            .unwrap_or_else(|e| format!("(review step failed: {e})"));

        assemble_triage_report(&research, &verified, &final_review)
    }

    /// Entry point for the `deepseek_live_lab` tool. v1 runs the rigid triage
    /// pipeline (§run_triage) on a caller-supplied failure context and returns the
    /// verified multi-section report. (The v4-pro lab-orchestration layer — which
    /// launches + drives the run to PRODUCE the failure context — is wired next.)
    fn call_live_lab(&self, args: &Value) -> ToolCallResult {
        let target = get_str(args, "target")
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .unwrap_or("(unspecified)")
            .to_string();
        let failure_context = match get_str(args, "failure_context") {
            Some(c) if !c.trim().is_empty() => c.to_string(),
            _ => {
                return tool_error(
                    "'failure_context' is required: provide the failed run's stage output / report \
                     excerpt / daemon logs (or a report_dir path the grounded agents can read).",
                );
            }
        };
        let max_steps = args
            .get("max_steps")
            .and_then(|v| v.as_u64())
            .map(|n| n.clamp(1, AGENT_HARD_MAX_STEPS))
            .unwrap_or(AGENT_DEFAULT_MAX_STEPS);

        // The pipeline runs for minutes (three grounded agents incl. v4-pro at max
        // reasoning) — far past the MCP client's request timeout. So run it ASYNC:
        // store a Running job, spawn the pipeline on a worker thread, and return the
        // job id immediately. The caller polls `deepseek_live_lab_result`.
        let job_id = self.new_job_id("triage");
        if let Ok(mut jobs) = self.jobs.lock() {
            jobs.insert(
                job_id.clone(),
                TriageJob::Running {
                    started: Instant::now(),
                },
            );
        }
        self.write_job_record(
            &job_id,
            &json!({
                "job_id": job_id,
                "kind": "triage",
                "state": "running",
                "area": target,
                "started_unix": now_unix(),
            }),
        );

        let worker = self.clone();
        let jid = job_id.clone();
        let target_label = target.clone();
        let ctx = format!("Target under test: {target}\n\n{failure_context}");
        std::thread::spawn(move || {
            let report = worker.run_triage(&ctx, max_steps);
            let body = format!(
                "[deepseek live-lab triage | target={target_label} | budget={max_steps}/step]\n\n{report}"
            );
            worker.finish_job(&jid, body);
        });

        ToolCallResult {
            content: text_content(format!(
                "Triage job started: `{job_id}` (target: {target}). The rigid pipeline (flash \
                 research → flash verify → v4-pro max review) runs ~1-3 min. Poll \
                 `deepseek_live_lab_result` with job_id=\"{job_id}\" every ~30-60s until it returns \
                 the report."
            )),
            is_error: None,
        }
    }

    /// Poll an async triage job. Non-blocking: returns the report when done, or a
    /// "still running" status with elapsed seconds — never blocks, so the poll
    /// itself can't trip the MCP request timeout.
    fn call_live_lab_result(&self, args: &Value) -> ToolCallResult {
        let job_id = match get_str(args, "job_id") {
            Some(j) if !j.trim().is_empty() => j.trim(),
            _ => return tool_error("'job_id' is required (from the deepseek_live_lab response)."),
        };

        // Fast path: the in-memory map (this server lifetime). A poisoned lock is
        // not fatal here — fall through to the on-disk record instead of erroring.
        if let Ok(jobs) = self.jobs.lock() {
            match jobs.get(job_id) {
                Some(TriageJob::Done(report)) => {
                    return ToolCallResult {
                        content: text_content(report.clone()),
                        is_error: None,
                    };
                }
                Some(TriageJob::Running { started }) => {
                    return ToolCallResult {
                        content: text_content(format!(
                            "Job `{job_id}` still running ({}s elapsed). Poll again in ~30-60s.",
                            started.elapsed().as_secs()
                        )),
                        is_error: None,
                    };
                }
                None => {}
            }
        }

        // Reload-survival fallback: the in-memory map was wiped on a server
        // restart, but every job persists a record under DEEPSEEK_JOBS_SUBDIR.
        let Some(rec) = self.read_job_record(job_id) else {
            return tool_error(&format!(
                "unknown job_id '{job_id}' — no in-memory entry and no persisted record under \
                 {DEEPSEEK_JOBS_SUBDIR}/. It was likely never started under this id; re-run the \
                 originating tool."
            ));
        };
        let state = rec.get("state").and_then(|s| s.as_str()).unwrap_or("");
        if state == "done" {
            // The worker finished and persisted its report before (or after) the
            // reload — return it verbatim.
            let report = rec
                .get("report_text")
                .and_then(|s| s.as_str())
                .unwrap_or("(job record marked done but carried no report_text)");
            return ToolCallResult {
                content: text_content(report.to_string()),
                is_error: None,
            };
        }

        // state == running, but the in-memory worker is gone (reload). For a
        // lab_run, the detached orchestrator may have finished anyway and written
        // its completion artifact — surface that outcome so the run isn't orphaned.
        let area = rec
            .get("area")
            .and_then(|s| s.as_str())
            .unwrap_or("(unknown)");
        if let Some(report_dir) = rec.get("report_dir").and_then(|s| s.as_str())
            && let Some((overall, first_failed)) = self.read_orchestrate_outcome(report_dir)
        {
            let dry_run = rec
                .get("dry_run")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let verdict = if dry_run {
                "DRY-RUN finished (not live evidence)".to_string()
            } else {
                overall
            };
            let failed_line = first_failed
                .as_deref()
                .map(|s| format!("First failed stage: `{s}`.\n"))
                .unwrap_or_default();
            return ToolCallResult {
                content: text_content(format!(
                    "# Live-lab run `{job_id}` (area: {area}) — orchestrator FINISHED, but the \
                     deepseek MCP server RELOADED mid-run so auto-triage did NOT run.\n\n\
                     Overall status: **{verdict}**.\n{failed_line}\n\
                     The detached orchestrator survived the reload and wrote its report to \
                     `{report_dir}` (completion artifact `{ORCHESTRATE_RESULT_REL}` present). \
                     Auto-triage was lost with the in-memory worker.\n\n\
                     Next: inspect the report dir (run_summary.md / state/stages.tsv / per-stage \
                     logs under it), or call `deepseek_live_lab` manually with the failing stage's \
                     evidence + this report_dir to get the triage report."
                )),
                is_error: None,
            };
        }

        // state == running, no completion artifact yet → genuinely still in flight
        // (the orchestrator re-parented to init and is still working).
        let elapsed = rec
            .get("started_unix")
            .and_then(|v| v.as_u64())
            .map(|s| now_unix().saturating_sub(s))
            .unwrap_or(0);
        ToolCallResult {
            content: text_content(format!(
                "Job `{job_id}` (area: {area}) still running ({elapsed}s elapsed since start; the \
                 deepseek MCP server reloaded but the detached orchestrator survives). No \
                 completion artifact yet — poll again in ~30-60s."
            )),
            is_error: None,
        }
    }

    /// Run the docs-sync grounded agent: a single read-only, repo-reads-only
    /// pass that PROPOSES (never applies) the exact documentation edits needed to
    /// keep the repo docs in sync with a lab-verified fix. Reuses the same
    /// grounded loop as deepseek_agent but with the docs-sync system prompt and
    /// the repo-reads-only tool set (no lab/guest/cargo tools). Writes nothing.
    fn run_doc_sync(&self, prompt: &str, model: &str, max_steps: u64) -> Result<String, String> {
        self.run_grounded(
            "doc-sync",
            DOC_SYNC_SYSTEM_PROMPT,
            prompt,
            model,
            max_steps,
            AgentToolset::DocsRepoReadOnly,
        )
    }

    /// Entry point for the `deepseek_doc_sync` tool. PROPOSE-ONLY and READ-ONLY:
    /// given a lab-verified fix (`change_summary` + optional commit/evidence/
    /// doc_hints), it proposes the exact docs-only edits to keep the repo docs in
    /// sync. It writes NOTHING — a human applies the proposed edits. Runs ASYNC
    /// like deepseek_live_lab: returns a job_id immediately; the caller polls the
    /// existing `deepseek_live_lab_result` tool for the structured report.
    fn call_doc_sync(&self, args: &Value) -> ToolCallResult {
        let change_summary = match get_str(args, "change_summary") {
            Some(s) if !s.trim().is_empty() => s.trim().to_string(),
            _ => {
                return tool_error(
                    "'change_summary' is required: describe what was fixed/patched/verified so the \
                     docs-sync agent knows what the docs must now reflect.",
                );
            }
        };
        let commit = get_str(args, "commit")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("(not provided)")
            .to_string();
        let evidence = get_str(args, "evidence")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("(not provided)")
            .to_string();
        let doc_hints = get_str(args, "doc_hints")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("(none — survey the active ledgers + indexes yourself)")
            .to_string();
        let model = resolve_model(get_str(args, "model").unwrap_or("flash"));
        let max_steps = args
            .get("max_steps")
            .and_then(|v| v.as_u64())
            .map(|n| n.clamp(1, AGENT_HARD_MAX_STEPS))
            .unwrap_or(AGENT_DEFAULT_MAX_STEPS);

        // The grounded pass reads several docs before proposing edits, so it can
        // run past the MCP request timeout. Run it ASYNC exactly like the triage
        // pipeline: store a Running job, spawn the worker, return the job id; the
        // caller polls the SAME `deepseek_live_lab_result` tool.
        let job_id = self.new_job_id("docsync");
        if let Ok(mut jobs) = self.jobs.lock() {
            jobs.insert(
                job_id.clone(),
                TriageJob::Running {
                    started: Instant::now(),
                },
            );
        }
        self.write_job_record(
            &job_id,
            &json!({
                "job_id": job_id,
                "kind": "docsync",
                "state": "running",
                "area": change_summary,
                "started_unix": now_unix(),
            }),
        );

        let user_prompt = format!(
            "A lab-verified fix has landed. Propose the docs-only edits to keep the repo docs in \
             sync with it.\n\n\
             ## Change summary (what was fixed/patched/verified)\n{change_summary}\n\n\
             ## Commit(s)\n{commit}\n\n\
             ## Verifying evidence (lab run id / run-matrix row / stage)\n{evidence}\n\n\
             ## Doc hints (likely-affected docs)\n{doc_hints}\n\n\
             Follow your docs-sync instructions exactly: FIRST read the current docs, then emit the \
             structured edit list (file / old_string / new_string / rationale) and the \
             considered-but-no-change list. Do NOT invent evidence, status, dates, or commit SHAs \
             beyond what is asserted above. You PROPOSE ONLY — you write nothing; a human applies \
             your edits."
        );

        let worker = self.clone();
        let jid = job_id.clone();
        let model_owned = model.to_string();
        std::thread::spawn(move || {
            let report = worker
                .run_doc_sync(&user_prompt, &model_owned, max_steps)
                .unwrap_or_else(|e| format!("(docs-sync proposal failed: {e})"));
            let body = format!(
                "[deepseek/{model_owned} | DOC-SYNC (propose-only, read-only) | budget={max_steps}/step]\n\n{report}"
            );
            worker.finish_job(&jid, body);
        });

        ToolCallResult {
            content: text_content(format!(
                "Docs-sync proposal started: `{job_id}` (model: {model}). A read-only, \
                 repo-reads-only agent reads the current docs, then proposes the exact docs-only \
                 edits — it writes NOTHING; you apply them. Poll `deepseek_live_lab_result` with \
                 job_id=\"{job_id}\" every ~20-40s until it returns the structured edit list."
            )),
            is_error: None,
        }
    }

    /// Resolve the lab inventory alias for a platform ("macos"/"windows"/"linux").
    /// Linux entries carry no `platform` field (→ "linux"). Read-only; confined.
    fn inventory_alias_for_platform(&self, platform: &str) -> Option<String> {
        let canon = self.confine(LAB_INVENTORY_PATH).ok()?;
        let body = rustynet_mcp::read_file_capped(&canon, 4 * 1024 * 1024).ok()?;
        let inv: Value = serde_json::from_str(&body).ok()?;
        let entries = inv.get("entries")?.as_array()?;
        for e in entries {
            let p = e
                .get("platform")
                .and_then(|v| v.as_str())
                .filter(|p| !p.is_empty())
                .unwrap_or("linux");
            if p == platform
                && let Some(a) = e.get("alias").and_then(|v| v.as_str())
            {
                return Some(a.to_string());
            }
        }
        None
    }

    /// Recovery-only stale process cleanup. Interrupted/reloaded runs can leave
    /// `live_linux_lab_orchestrator.sh` children alive after the DeepSeek job
    /// record is terminal or absent. Kill only process groups tied to a
    /// DeepSeek-owned report dir whose job record is not currently running.
    fn terminate_stale_lab_orchestrators(&self) -> Vec<String> {
        let outcome = run_with_timeout(
            "ps",
            &["-axo", "pid,ppid,pgid,command"],
            &self.repo_root,
            &[],
            Duration::from_secs(SUBPROC_TIMEOUT_SECS),
        );
        let Ok(outcome) = outcome else {
            return vec!["ps unavailable; skipped stale process cleanup".to_string()];
        };
        if !outcome.success {
            return vec![format!(
                "ps failed; skipped stale process cleanup: {}",
                outcome.stderr.trim()
            )];
        }

        let mut groups = std::collections::HashSet::new();
        let mut notes = Vec::new();
        for line in outcome.stdout.lines() {
            if !line.contains("live_linux_lab_orchestrator.sh")
                || !line.contains("state/deepseek-lab-labrun-")
            {
                continue;
            }
            let mut parts = line.split_whitespace();
            let _pid = parts.next();
            let _ppid = parts.next();
            let Some(pgid_s) = parts.next() else {
                continue;
            };
            let Ok(pgid) = pgid_s.parse::<i32>() else {
                continue;
            };
            let Some(job_id) = extract_labrun_job_id(line) else {
                continue;
            };
            let is_running = self
                .read_job_record(&job_id)
                .and_then(|r| r.get("state").and_then(|s| s.as_str()).map(str::to_string))
                .as_deref()
                == Some("running");
            if is_running {
                continue;
            }
            if groups.insert(pgid) {
                terminate_process_group(pgid);
                notes.push(format!("killed stale pgid {pgid} for `{job_id}`"));
            }
        }
        notes
    }

    /// Resolve a Linux backbone alias by its lab_role (exit/client/relay/aux).
    /// Used by the next-target chooser so generated runs carry the same explicit
    /// topology humans use in the runbooks.
    fn inventory_alias_for_lab_role(&self, role: &str) -> Option<String> {
        let canon = self.confine(LAB_INVENTORY_PATH).ok()?;
        let body = rustynet_mcp::read_file_capped(&canon, 4 * 1024 * 1024).ok()?;
        let inv: Value = serde_json::from_str(&body).ok()?;
        let entries = inv.get("entries")?.as_array()?;
        for e in entries {
            let platform = e
                .get("platform")
                .and_then(|v| v.as_str())
                .filter(|p| !p.is_empty())
                .unwrap_or("linux");
            if platform == "linux"
                && e.get("lab_role").and_then(|v| v.as_str()) == Some(role)
                && let Some(a) = e.get("alias").and_then(|v| v.as_str())
            {
                return Some(a.to_string());
            }
        }
        None
    }

    fn next_live_lab_target(&self, force: Option<&str>) -> Result<LiveLabTarget, String> {
        if let Some(key) = force {
            return self.target_from_key(key, "explicit operator target");
        }

        let matrix = self.read_run_matrix_rows()?;
        if let Some((header, rows)) = matrix.as_ref()
            && let Some(latest) = rows.last()
        {
            let col = |name: &str| header.iter().position(|c| c == name);
            let g = |name: &str| {
                col(name)
                    .and_then(|i| latest.get(i))
                    .map(|s| s.trim())
                    .unwrap_or("")
            };
            let overall = g("overall_result").to_ascii_lowercase();
            let failed = g("first_failed_stage");
            if !failed.is_empty()
                && !overall.contains("pass")
                && let Some(key) = key_for_stage_or_cell(failed)
            {
                return self.target_from_key(
                    key,
                    &format!("latest run failed at `{failed}`; retry focused cell"),
                );
            }

            // Release-blocking macOS/Windows role cells first. Windows blind_exit
            // is intentionally unsupported by design, so it is not auto-targeted.
            for (cell, key) in [
                ("macos_exit", "macos_exit"),
                ("macos_blind_exit", "macos_blind_exit"),
                ("macos_anchor", "macos_anchor"),
                ("windows_anchor", "windows_anchor"),
                ("windows_relay", "windows_relay"),
                ("windows_exit", "windows_exit"),
            ] {
                let status = g(cell).to_ascii_lowercase();
                if !status.contains("pass") && !status.contains('✅') {
                    return self.target_from_key(
                        key,
                        &format!("matrix cell `{cell}` is not currently pass (`{}`)", g(cell)),
                    );
                }
            }
        }

        self.target_from_key("full", "no failing focused cell found; run full matrix")
    }

    fn read_run_matrix_rows(&self) -> Result<Option<RunMatrixRows>, String> {
        let path = self
            .repo_root
            .join("documents/operations/live_lab_run_matrix.csv");
        if !path.is_file() {
            return Ok(None);
        }
        let body = rustynet_mcp::read_file_capped(&path, 16 * 1024 * 1024)?;
        let mut lines = body.lines();
        let header = parse_csv_line(lines.next().unwrap_or(""));
        let rows: Vec<Vec<String>> = lines
            .filter(|l| !l.trim().is_empty())
            .map(parse_csv_line)
            .collect();
        Ok(Some((header, rows)))
    }

    fn target_from_key(&self, key: &str, reason: &str) -> Result<LiveLabTarget, String> {
        let mut m = Map::new();
        let area: String;
        match key {
            "macos_admin" => {
                area = "macOS admin live issue".into();
                m.insert("macos".into(), json!(true));
                m.insert("admin_platform".into(), json!("macos"));
                m.insert("skip_linux_live_suite".into(), json!(true));
                m.insert("legacy_bash".into(), json!(true));
            }
            "windows_admin" => {
                area = "Windows admin live issue".into();
                m.insert("windows".into(), json!(true));
                m.insert("admin_platform".into(), json!("windows"));
                m.insert("skip_linux_live_suite".into(), json!(true));
            }
            "macos_exit" => {
                area = "macOS exit live verification".into();
                m.insert("macos".into(), json!(true));
                m.insert("macos_promote_exit".into(), json!(true));
                m.insert("skip_linux_live_suite".into(), json!(true));
                m.insert("legacy_bash".into(), json!(true));
                self.add_default_backbone(&mut m, true);
            }
            "windows_exit" => {
                area = "Windows exit live verification".into();
                m.insert("windows".into(), json!(true));
                m.insert("exit_platform".into(), json!("windows"));
                m.insert("skip_linux_live_suite".into(), json!(true));
                self.add_default_backbone(&mut m, false);
            }
            "macos_blind_exit" => {
                area = "macOS blind_exit live verification".into();
                m.insert("macos".into(), json!(true));
                m.insert("blind_exit_platform".into(), json!("macos"));
                m.insert("skip_linux_live_suite".into(), json!(true));
                m.insert("legacy_bash".into(), json!(true));
            }
            "macos_anchor" => {
                area = "macOS anchor live bundle-pull".into();
                m.insert("macos".into(), json!(true));
                m.insert("anchor_platform".into(), json!("macos"));
                m.insert("skip_linux_live_suite".into(), json!(true));
                m.insert("legacy_bash".into(), json!(true));
            }
            "windows_anchor" => {
                area = "Windows anchor live bundle-pull".into();
                m.insert("windows".into(), json!(true));
                m.insert("anchor_platform".into(), json!("windows"));
                m.insert("skip_linux_live_suite".into(), json!(true));
            }
            "macos_relay" => {
                area = "macOS relay lifecycle".into();
                m.insert("macos".into(), json!(true));
                m.insert("relay_platform".into(), json!("macos"));
                m.insert("skip_linux_live_suite".into(), json!(true));
                m.insert("legacy_bash".into(), json!(true));
            }
            "windows_relay" => {
                area = "Windows relay lifecycle".into();
                m.insert("windows".into(), json!(true));
                m.insert("relay_platform".into(), json!("windows"));
                m.insert("skip_linux_live_suite".into(), json!(true));
            }
            "full" => {
                area = "full cross-platform live lab".into();
                m.insert("macos".into(), json!(true));
                m.insert("windows".into(), json!(true));
                self.add_default_backbone(&mut m, true);
            }
            other => {
                return Err(format!(
                    "unknown target '{other}'; use one of macos_admin|windows_admin|macos_exit|\
                     windows_exit|macos_blind_exit|macos_anchor|windows_anchor|macos_relay|\
                     windows_relay|full"
                ));
            }
        }
        m.insert("area".into(), json!(area.clone()));
        Ok(LiveLabTarget {
            key: key.to_string(),
            area,
            reason: reason.to_string(),
            args: Value::Object(m),
        })
    }

    fn add_default_backbone(&self, m: &mut Map<String, Value>, include_entry: bool) {
        if let Some(exit) = self.inventory_alias_for_lab_role("exit") {
            m.insert("exit_vm".into(), json!(exit));
        }
        if let Some(client) = self.inventory_alias_for_lab_role("client") {
            m.insert("client_vm".into(), json!(client));
        }
        if include_entry
            && let Some(entry) = self
                .inventory_alias_for_lab_role("relay")
                .or_else(|| self.inventory_alias_for_lab_role("aux"))
        {
            m.insert("entry_vm".into(), json!(entry));
        }
    }

    /// Count in-flight lab-run jobs — the lab is a singleton, never two
    /// orchestrations on the VMs at once. Unions the in-memory map (this server
    /// lifetime) with the persisted records under DEEPSEEK_JOBS_SUBDIR, so a reloaded
    /// server still sees an orphaned-but-still-running orchestrator from a prior
    /// lifetime and the singleton gate keeps holding. A disk record counts as
    /// in-flight only while state==running AND its report dir has NOT yet produced
    /// the completion artifact (otherwise the orchestrator already finished).
    fn running_lab_jobs(&self) -> usize {
        use std::collections::HashSet;
        let mut running: HashSet<String> = HashSet::new();
        if let Ok(jobs) = self.jobs.lock() {
            for (id, j) in jobs.iter() {
                if id.starts_with("labrun-") && matches!(j, TriageJob::Running { .. }) {
                    running.insert(id.clone());
                }
            }
        }
        if let Ok(entries) = std::fs::read_dir(self.jobs_dir()) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                let Some(job_id) = name.strip_suffix(".json") else {
                    continue;
                };
                if !job_id.starts_with("labrun-") || running.contains(job_id) {
                    continue;
                }
                let Some(rec) = self.read_job_record(job_id) else {
                    continue;
                };
                if rec.get("state").and_then(|s| s.as_str()) != Some("running") {
                    continue;
                }
                // Still running per the record — but it only counts as in-flight
                // when BOTH:
                //   (a) its orchestrator has NOT written the completion artifact
                //       (otherwise the run is effectively done), AND
                //   (b) the orchestrator is still alive — i.e. no pid was recorded
                //       (conservative: keep counting an indeterminate record) OR a
                //       recorded pid is still alive. A recorded-but-DEAD pid with
                //       no artifact = a crashed/killed run; it must NOT peg the
                //       singleton slot, so the next deepseek_lab_run can proceed
                //       even before anyone runs deepseek_reconcile_jobs.
                let no_artifact = rec
                    .get("report_dir")
                    .and_then(|s| s.as_str())
                    .map(|rd| self.read_orchestrate_outcome(rd).is_none())
                    .unwrap_or(true);
                let orchestrator_alive = match Self::job_orchestrator_pid(&rec) {
                    Some(pid) => pid_is_alive(pid),
                    None => {
                        // No pid recorded. The worker records it within ~1s of
                        // spawning the orchestrator, so a no-pid record older than
                        // RECONCILE_NO_PID_STALE_SECS is a phantom (the worker died
                        // before the spawn) and must NOT peg the slot — let the
                        // gate self-heal even before deepseek_reconcile_jobs runs.
                        // A younger no-pid record is still in its startup window;
                        // count it conservatively as in flight.
                        !Self::record_no_pid_stale(&rec)
                    }
                };
                if no_artifact && orchestrator_alive {
                    running.insert(job_id.to_string());
                }
            }
        }
        running.len()
    }

    /// Reconcile a SINGLE persisted labrun record, mutating it on disk if its
    /// `state=running` no longer reflects reality. Returns `Some(change)` when the
    /// record was reclassified (done / crashed), `None` when it was left running
    /// (genuinely in flight, or indeterminate — conservative). Idempotent: a
    /// record already in a terminal state, or one for a non-labrun job, is a
    /// no-op. Shared by the per-job and scan-all paths of the reconcile tool.
    fn reconcile_one_record(&self, job_id: &str) -> Option<ReconcileChange> {
        let rec = self.read_job_record(job_id)?;
        let old_state = rec.get("state").and_then(|s| s.as_str()).unwrap_or("");
        // Only "running" records can be stale; terminal records are left alone.
        if old_state != "running" {
            return None;
        }
        let report_dir = rec.get("report_dir").and_then(|s| s.as_str());

        // Case 1: completion artifact present → the orchestrator FINISHED but the
        // worker died before recording the result. Recover the report exactly as
        // deepseek_live_lab_result's reload fallback does (overall_status + first
        // failed stage) and mark the record done.
        if let Some(rd) = report_dir
            && let Some((overall, first_failed)) = self.read_orchestrate_outcome(rd)
        {
            let dry_run = rec
                .get("dry_run")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let verdict = if dry_run {
                "DRY-RUN finished (not live evidence)".to_string()
            } else {
                overall
            };
            let area = rec
                .get("area")
                .and_then(|s| s.as_str())
                .unwrap_or("(unknown)");
            let failed_line = first_failed
                .as_deref()
                .map(|s| format!("First failed stage: `{s}`.\n"))
                .unwrap_or_default();
            let report = format!(
                "# Live-lab run `{job_id}` (area: {area}) — RECONCILED to done.\n\n\
                 Overall status: **{verdict}**.\n{failed_line}\n\
                 The orchestrator wrote its completion artifact at `{rd}` \
                 (`{ORCHESTRATE_RESULT_REL}`), but the deepseek worker died before recording \
                 the result, so the record was stuck at `state=running`.\n\n\
                 (reconciled: orchestrator finished; the worker died before recording the \
                 result). Inspect the report dir for run_summary.md / per-stage logs."
            );
            // finish_job merges into the existing record (preserving the static
            // creation fields) and stamps state=done + report_text, the same
            // shape deepseek_live_lab_result returns.
            self.finish_job(job_id, report);
            return Some(ReconcileChange {
                job_id: job_id.to_string(),
                kind: "labrun".to_string(),
                old_state: "running".to_string(),
                new_state: "done".to_string(),
                reason: "orchestrator finished (completion artifact present); worker died before \
                         recording the result"
                    .to_string(),
            });
        }

        // Case 2: a pid was recorded AND it is dead, with no completion artifact →
        // the orchestrator CRASHED or was killed mid-run. Mark the record crashed.
        if let Some(pid) = Self::job_orchestrator_pid(&rec)
            && !pid_is_alive(pid)
        {
            let mut rec = rec;
            if let Some(obj) = rec.as_object_mut() {
                obj.insert("state".into(), json!("crashed"));
                obj.insert("finished_unix".into(), json!(now_unix()));
                obj.insert(
                    "reconcile_note".into(),
                    json!(format!(
                        "(reconciled: orchestrator pid {pid} is dead and no completion artifact \
                         was written)"
                    )),
                );
            }
            self.write_job_record(job_id, &rec);
            // Drop any stale in-memory Running entry so the slot frees immediately.
            if let Ok(mut jobs) = self.jobs.lock() {
                jobs.remove(job_id);
            }
            return Some(ReconcileChange {
                job_id: job_id.to_string(),
                kind: "labrun".to_string(),
                old_state: "running".to_string(),
                new_state: "crashed".to_string(),
                reason: format!(
                    "orchestrator pid {pid} is dead and no completion artifact was written"
                ),
            });
        }

        // Case 2.5: NO pid was ever recorded, no artifact, and the record is older
        // than RECONCILE_NO_PID_STALE_SECS. The worker records the orchestrator pid
        // within ~1s of spawning it, so a no-pid record this old means the worker
        // died BEFORE the spawn (e.g. a stdio driver disconnected right after the
        // async ack, killing the server before the detached orchestrator launched).
        // It can never be repaired by the pid-liveness path (Case 2), so it would
        // peg the singleton forever. Reclassify it crashed.
        if Self::record_no_pid_stale(&rec) {
            let started = rec
                .get("started_unix")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let age = now_unix().saturating_sub(started);
            let mut rec = rec;
            if let Some(obj) = rec.as_object_mut() {
                obj.insert("state".into(), json!("crashed"));
                obj.insert("finished_unix".into(), json!(now_unix()));
                obj.insert(
                    "reconcile_note".into(),
                    json!(format!(
                        "(reconciled: no orchestrator pid was ever recorded and no completion \
                         artifact was written {age}s after start — the worker died before \
                         spawning the orchestrator)"
                    )),
                );
            }
            self.write_job_record(job_id, &rec);
            if let Ok(mut jobs) = self.jobs.lock() {
                jobs.remove(job_id);
            }
            return Some(ReconcileChange {
                job_id: job_id.to_string(),
                kind: "labrun".to_string(),
                old_state: "running".to_string(),
                new_state: "crashed".to_string(),
                reason: format!(
                    "no orchestrator pid ever recorded and no completion artifact {age}s after \
                     start (worker died before spawning the orchestrator)"
                ),
            });
        }

        // Case 3: pid alive, OR no pid recorded but still inside the startup window
        // (younger than RECONCILE_NO_PID_STALE_SECS) → genuinely in flight, or
        // indeterminate. Be conservative: leave it running.
        None
    }

    /// Entry point for `deepseek_reconcile_jobs`: self-service repair of stale
    /// `state=running` labrun records so a crashed/killed run can no longer block
    /// the singleton gate forever. With `job_id` it reconciles that one record;
    /// otherwise it scans EVERY record under DEEPSEEK_JOBS_SUBDIR. Read-only with
    /// respect to the lab/guests/repo — it only rewrites this server's own job
    /// records (atomic tmp+rename, as every job-record write does).
    fn call_reconcile_jobs(&self, args: &Value) -> ToolCallResult {
        let single = get_str(args, "job_id")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        // The set of job ids to consider: the one requested, or every persisted
        // labrun record.
        let job_ids: Vec<String> = if let Some(id) = single {
            vec![id]
        } else {
            let mut ids = Vec::new();
            if let Ok(entries) = std::fs::read_dir(self.jobs_dir()) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    if let Some(job_id) = name.strip_suffix(".json")
                        && job_id.starts_with("labrun-")
                    {
                        ids.push(job_id.to_string());
                    }
                }
            }
            ids.sort();
            ids
        };

        let mut scanned = 0usize;
        let mut left_running = 0usize;
        let mut changes: Vec<ReconcileChange> = Vec::new();
        for job_id in &job_ids {
            // Only count records that exist and are currently "running" toward the
            // scan total; a missing/terminal record is not a reconcile candidate.
            let Some(rec) = self.read_job_record(job_id) else {
                continue;
            };
            if rec.get("state").and_then(|s| s.as_str()) != Some("running") {
                continue;
            }
            scanned += 1;
            match self.reconcile_one_record(job_id) {
                Some(change) => changes.push(change),
                None => left_running += 1,
            }
        }

        let reconciled_done = changes.iter().filter(|c| c.new_state == "done").count();
        let reconciled_crashed = changes.iter().filter(|c| c.new_state == "crashed").count();

        let mut out = String::new();
        out.push_str("# deepseek_reconcile_jobs\n\n");
        out.push_str(&format!(
            "Scanned {scanned} running labrun record(s): reconciled {reconciled_done} to \
             **done**, {reconciled_crashed} to **crashed**; left {left_running} **running** \
             (genuinely in flight or indeterminate).\n",
        ));
        if changes.is_empty() {
            out.push_str(
                "\nNo stale records to repair — every running record is still genuinely in \
                 flight (live orchestrator, no completion artifact).\n",
            );
        } else {
            out.push_str("\nChanges:\n");
            for c in &changes {
                out.push_str(&format!(
                    "- `{}` ({}): {} → {} — {}\n",
                    c.job_id, c.kind, c.old_state, c.new_state, c.reason
                ));
            }
        }
        ToolCallResult {
            content: text_content(out),
            is_error: None,
        }
    }

    /// Read-only next-target chooser for the autonomous loop. It prefers the
    /// latest failed stage, then role cells whose current matrix status is not
    /// pass, using explicit role-platform selectors so the launched run is
    /// focused and cheap instead of a blind full sweep.
    fn call_next_live_lab_target(&self, args: &Value) -> ToolCallResult {
        let force = get_str(args, "target")
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let target = match self.next_live_lab_target(force) {
            Ok(t) => t,
            Err(e) => return tool_error(&e),
        };
        ToolCallResult {
            content: text_content(format!(
                "# deepseek_next_live_lab_target\n\n\
                 key: `{}`\narea: `{}`\nreason: {}\n\n\
                 deepseek_lab_run args:\n```json\n{}\n```\n",
                target.key,
                target.area,
                target.reason,
                serde_json::to_string_pretty(&target.args).unwrap_or_else(|_| "{}".into())
            )),
            is_error: None,
        }
    }

    /// One-call autonomous loop driver for simple agents:
    /// 1. reconcile stale labrun records after interruption,
    /// 2. refuse to launch if a labrun is genuinely in flight,
    /// 3. pick the next matrix-backed target,
    /// 4. call deepseek_lab_run with the right selectors.
    fn call_autonomous_live_lab_loop(&self, args: &Value) -> ToolCallResult {
        let _ = self.call_reconcile_jobs(&json!({}));
        let in_flight = self.running_lab_jobs();
        if in_flight > 0 {
            return ToolCallResult {
                content: text_content(format!(
                    "# deepseek_autonomous_live_lab_loop\n\n\
                     {in_flight} labrun already in flight. Do not launch another singleton run.\n\n\
                     Next call: `deepseek_live_lab_result` on the running job, or \
                     `deepseek_reconcile_jobs` if the prior run was interrupted."
                )),
                is_error: None,
            };
        }

        let force = get_str(args, "target")
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let mut target = match self.next_live_lab_target(force) {
            Ok(t) => t,
            Err(e) => return tool_error(&e),
        };
        overlay_loop_options(&mut target.args, args);
        self.call_lab_run(&target.args)
    }

    /// Async recovery pass for interrupted labs. This is deliberately separate
    /// from `deepseek_lab_run`: it repairs stale DeepSeek job records, then runs
    /// the Rust orchestrator only to the ready gate (`--stop-after-ready`) so VMs
    /// are powered/reachable before the next labrun. It never calls DeepSeek.
    fn call_recover_lab_environment(&self, args: &Value) -> ToolCallResult {
        let force = args.get("force").and_then(|v| v.as_bool()).unwrap_or(false);
        let dry_run = args
            .get("dry_run")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let in_flight = self.running_lab_jobs();
        if in_flight > 0 && !force {
            return tool_error(
                "a deepseek_lab_run is still in flight; poll deepseek_live_lab_result or pass \
                 force=true only after proving the run is dead/interrupted",
            );
        }
        let _ = self.call_reconcile_jobs(&json!({}));
        let stale_kills = self.terminate_stale_lab_orchestrators();

        let job_id = self.new_job_id("recover");
        let report_dir = format!("state/deepseek-recover-{job_id}");
        if let Ok(mut jobs) = self.jobs.lock() {
            jobs.insert(
                job_id.clone(),
                TriageJob::Running {
                    started: Instant::now(),
                },
            );
        }
        self.write_job_record(
            &job_id,
            &json!({
                "job_id": job_id,
                "kind": "recover",
                "state": "running",
                "area": "lab environment recovery",
                "report_dir": report_dir,
                "log_path": self.jobs_dir().join(format!("{job_id}.log")).to_string_lossy(),
                "started_unix": now_unix(),
            }),
        );

        let worker = self.clone();
        let jid = job_id.clone();
        std::thread::spawn(move || {
            let stale_cleanup = if stale_kills.is_empty() {
                "- none".to_string()
            } else {
                stale_kills
                    .iter()
                    .map(|s| format!("- {s}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            let stale_count = stale_kills.len();
            let ssh = home_path(LAB_SSH_IDENTITY_REL);
            let kh = home_path(LAB_KNOWN_HOSTS_REL);
            let mut cargo_args: Vec<String> = ["run", "--quiet", "-p", "rustynet-cli", "--", "ops"]
                .iter()
                .map(|s| s.to_string())
                .collect();
            cargo_args.extend(recovery_orchestrator_args(
                LAB_INVENTORY_PATH,
                &ssh,
                &kh,
                &report_dir,
                dry_run,
            ));
            let arg_refs: Vec<&str> = cargo_args.iter().map(String::as_str).collect();
            let log_path = worker.jobs_dir().join(format!("{jid}.log"));
            if let Err(e) = std::fs::create_dir_all(worker.jobs_dir()) {
                worker.finish_job(
                    &jid,
                    format!("# Lab recovery — could not create log dir: {e}"),
                );
                return;
            }
            let mut child =
                match spawn_logged("cargo", &arg_refs, &worker.repo_root, &[], &log_path) {
                    Ok(c) => c,
                    Err(e) => {
                        worker.finish_job(
                            &jid,
                            format!("# Lab recovery — could not launch stop-after-ready pass: {e}"),
                        );
                        return;
                    }
                };
            worker.record_orchestrator_pid(&jid, child.id());
            let start = Instant::now();
            let timeout = Duration::from_secs(LAB_ORCHESTRATOR_TIMEOUT_SECS);
            let (success, timed_out) = loop {
                match child.try_wait() {
                    Ok(Some(status)) => break (status.success(), false),
                    Ok(None) => {
                        if start.elapsed() >= timeout {
                            kill_child_group(&mut child);
                            let _ = child.wait();
                            break (false, true);
                        }
                        std::thread::sleep(Duration::from_millis(200));
                    }
                    Err(e) => {
                        worker.finish_job(
                            &jid,
                            format!("# Lab recovery — error waiting on stop-after-ready pass: {e}"),
                        );
                        return;
                    }
                }
            };
            let tail = tail_file(&log_path, 120).unwrap_or_default();
            let verdict = if timed_out {
                "TIMED OUT"
            } else if dry_run {
                "DRY-RUN"
            } else if success {
                "PASS"
            } else {
                "FAIL"
            };
            worker.finish_job(
                &jid,
                format!(
                    "# Lab environment recovery — {verdict}\n\n\
                     Reconciled stale DeepSeek lab records, stopped stale orchestrator process \
                     groups ({stale_count}), then ran \
                     `vm-lab-orchestrate-live-lab --stop-after-ready{}`.\n\n\
                     Stale process cleanup:\n{stale_cleanup}\n\n\
                     Report dir: `{report_dir}`\nLog: `{}`\n\n_log tail:_\n{}",
                    if dry_run { " --dry-run" } else { "" },
                    log_path.display(),
                    truncate_output(&tail, 80, 5000)
                ),
            );
        });

        ToolCallResult {
            content: text_content(format!(
                "Lab recovery started: `{job_id}`. It reconciles stale DeepSeek job records and \
                 runs the orchestrator to `--stop-after-ready`. Poll `deepseek_live_lab_result` \
                 with job_id=\"{job_id}\"."
            )),
            is_error: None,
        }
    }

    /// Entry point for `deepseek_lab_run`: the WHOLE pipeline in one call. The
    /// worker thread launches the hardened orchestrator (DETERMINISTIC — no LLM in
    /// the deploy path), waits for it, and on FAILURE runs the rigid triage
    /// pipeline on the run's evidence; on success it reports the pass. Async: the
    /// call returns a job_id, the caller polls deepseek_live_lab_result.
    fn call_lab_run(&self, args: &Value) -> ToolCallResult {
        let area = get_str(args, "area")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("(unspecified)")
            .to_string();
        let dry_run = args
            .get("dry_run")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let rebuild = get_str(args, "rebuild_nodes")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let max_steps = args
            .get("max_steps")
            .and_then(|v| v.as_u64())
            .map(|n| n.clamp(1, AGENT_HARD_MAX_STEPS))
            .unwrap_or(AGENT_DEFAULT_MAX_STEPS);
        let triage_on_failure = args
            .get("triage_on_failure")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        // Resolve macOS/Windows guests: explicit alias wins; `macos:true` /
        // `windows:true` auto-resolves from the inventory.
        let macos_vm = match get_str(args, "macos_vm") {
            Some(a) if !a.trim().is_empty() => Some(a.trim().to_string()),
            _ if args.get("macos").and_then(|v| v.as_bool()).unwrap_or(false) => {
                match self.inventory_alias_for_platform("macos") {
                    Some(a) => Some(a),
                    None => {
                        return tool_error("macos requested but no macOS guest in the inventory");
                    }
                }
            }
            _ => None,
        };
        let windows_vm = match get_str(args, "windows_vm") {
            Some(a) if !a.trim().is_empty() => Some(a.trim().to_string()),
            _ if args
                .get("windows")
                .and_then(|v| v.as_bool())
                .unwrap_or(false) =>
            {
                match self.inventory_alias_for_platform("windows") {
                    Some(a) => Some(a),
                    None => {
                        return tool_error(
                            "windows requested but no Windows guest in the inventory",
                        );
                    }
                }
            }
            _ => None,
        };

        // Linux backbone selectors (for disjoint concurrent runs) + the opt-in
        // concurrency switch. Default stays a singleton.
        let exit_vm = get_str(args, "exit_vm")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let client_vm = get_str(args, "client_vm")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        // Role-platform selectors: ELECT a mac/win node into the exit/relay/anchor/
        // blind_exit role so the focused role cell runs LIVE instead of skipping.
        // Each must be exactly one of {linux, macos, windows} — fail closed on any
        // other value rather than passing junk to the orchestrator.
        let validate_role_platform = |key: &str| -> Result<Option<String>, String> {
            match get_str(args, key).map(str::trim).filter(|s| !s.is_empty()) {
                None => Ok(None),
                Some(v @ ("linux" | "macos" | "windows")) => Ok(Some(v.to_string())),
                Some(other) => Err(format!(
                    "invalid {key} '{other}': must be one of linux|macos|windows"
                )),
            }
        };
        let exit_platform = match validate_role_platform("exit_platform") {
            Ok(v) => v,
            Err(e) => return tool_error(&e),
        };
        let relay_platform = match validate_role_platform("relay_platform") {
            Ok(v) => v,
            Err(e) => return tool_error(&e),
        };
        let anchor_platform = match validate_role_platform("anchor_platform") {
            Ok(v) => v,
            Err(e) => return tool_error(&e),
        };
        let admin_platform = match validate_role_platform("admin_platform") {
            Ok(v) => v,
            Err(e) => return tool_error(&e),
        };
        let blind_exit_platform = match validate_role_platform("blind_exit_platform") {
            Ok(v) => v,
            Err(e) => return tool_error(&e),
        };
        let macos_promote_exit = args
            .get("macos_promote_exit")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let legacy_bash = args
            .get("legacy_bash")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let entry_vm = get_str(args, "entry_vm")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let windows_only = args
            .get("windows_only")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        // Skip the ~30-45 min Linux live-validation suite and jump straight to
        // the mac/win role stages after setup. Pair with a role-platform
        // selector (exit_platform/relay_platform/anchor_platform/...) to drive
        // ONE mac/win cell fast instead of paying for the whole Linux lab.
        let skip_linux_live_suite = args
            .get("skip_linux_live_suite")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let allow_concurrent = args
            .get("allow_concurrent")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let limit = if allow_concurrent {
            MAX_CONCURRENT_LAB_RUNS
        } else {
            1
        };
        let in_flight = self.running_lab_jobs();
        if in_flight >= limit {
            return tool_error(&format!(
                "{in_flight} deepseek lab run(s) already in flight (limit {limit}{}) — poll \
                 deepseek_live_lab_result, or wait. For a parallel run pass allow_concurrent=true \
                 AND disjoint guests (a separate exit_vm/client_vm per run, e.g. macOS on one \
                 Debian backbone, Windows on another).",
                if allow_concurrent { "" } else { ", singleton" }
            ));
        }

        let job_id = self.new_job_id("labrun");
        // The report dir derives from the job_id ALONE (which is already unique
        // across restarts via the millis+pid+seq id), so it is reconstructable
        // from the persisted record after a reload. No pid suffix needed — the id
        // carries the uniqueness; the bare-derived dir is what the poll fallback
        // reads `orchestration/orchestrate_result.json` from.
        let report_dir = format!("state/deepseek-lab-{job_id}");
        if let Ok(mut jobs) = self.jobs.lock() {
            jobs.insert(
                job_id.clone(),
                TriageJob::Running {
                    started: Instant::now(),
                },
            );
        }
        self.write_job_record(
            &job_id,
            &json!({
                "job_id": job_id,
                "kind": "labrun",
                "state": "running",
                "area": area,
                "request_args": args.clone(),
                "report_dir": report_dir,
                "dry_run": dry_run,
                "triage_on_failure": triage_on_failure,
                "log_path": self.jobs_dir().join(format!("{job_id}.log")).to_string_lossy(),
                "started_unix": now_unix(),
            }),
        );

        // Build the ack message before `area` moves into the worker closure.
        let started_msg = format!(
            "Live-lab run started: `{job_id}` (area: {area}{}). The orchestrator runs \
             deterministically (no LLM in the deploy path); on failure the rigid triage pipeline \
             runs automatically. This takes many minutes — poll `deepseek_live_lab_result` with \
             job_id=\"{job_id}\" until it returns the report.",
            if dry_run { ", DRY-RUN" } else { "" }
        );
        let worker = self.clone();
        let jid = job_id.clone();
        std::thread::spawn(move || {
            let ssh = home_path(LAB_SSH_IDENTITY_REL);
            let kh = home_path(LAB_KNOWN_HOSTS_REL);
            // Concurrent runs get their own CARGO_TARGET_DIR so two `cargo run`s
            // don't serialize on the same build lock; the singleton default shares
            // the workspace target dir (faster — cargo cache hit, no recompile).
            let target_dir = format!("target-deepseek-{jid}");
            let env: Vec<(&str, &str)> = if allow_concurrent {
                vec![("CARGO_TARGET_DIR", target_dir.as_str())]
            } else {
                Vec::new()
            };
            let mut cargo_args: Vec<String> = ["run", "--quiet", "-p", "rustynet-cli", "--", "ops"]
                .iter()
                .map(|s| s.to_string())
                .collect();
            cargo_args.extend(build_orchestrator_args(
                LAB_INVENTORY_PATH,
                &ssh,
                &kh,
                &report_dir,
                macos_vm.as_deref(),
                windows_vm.as_deref(),
                exit_vm.as_deref(),
                client_vm.as_deref(),
                rebuild.as_deref(),
                exit_platform.as_deref(),
                relay_platform.as_deref(),
                anchor_platform.as_deref(),
                admin_platform.as_deref(),
                blind_exit_platform.as_deref(),
                entry_vm.as_deref(),
                macos_promote_exit,
                legacy_bash,
                dry_run,
                windows_only,
                skip_linux_live_suite,
            ));
            let arg_refs: Vec<&str> = cargo_args.iter().map(String::as_str).collect();

            // Spawn the orchestrator DETACHED — stdin null, stdout+stderr to a log
            // FILE (under the jobs dir, NOT the report dir, whose empty-dir
            // precondition the orchestrator enforces), its own process group. This
            // is the critical reload-survival change: previously the orchestrator's
            // pipes were captured by the server process (run_with_timeout →
            // Command::output()), so when the deepseek MCP server reloaded mid-run
            // the read end closed and the orchestrator got SIGPIPE on its next
            // write (observed as `bootstrap_hosts FAIL rc=141`). With the I/O on a
            // file, a server reload can no longer SIGPIPE-kill the run; the
            // detached orchestrator re-parents to init, runs to completion, and
            // writes its report dir, which the poll fallback then surfaces.
            let log_path = worker.jobs_dir().join(format!("{jid}.log"));
            if let Err(e) = std::fs::create_dir_all(worker.jobs_dir()) {
                worker.finish_job(
                    &jid,
                    format!(
                        "# Live-lab run: {area} — could not create the orchestrator log dir: {e}\n\n\
                         (infrastructure error, not a lab failure.)"
                    ),
                );
                return;
            }
            let mut child =
                match spawn_logged("cargo", &arg_refs, &worker.repo_root, &env, &log_path) {
                    Ok(c) => c,
                    Err(e) => {
                        worker.finish_job(
                        &jid,
                        format!(
                            "# Live-lab run: {area} — could not launch the orchestrator: {e}\n\n\
                             (Is `cargo` on PATH, the inventory ready, and SSH material present? \
                             This is an infrastructure error, not a lab failure.)"
                        ),
                    );
                        return;
                    }
                };

            // Record the orchestrator's pid in the running record NOW that the
            // child exists. The record written at job creation could not carry it
            // (the child wasn't spawned yet); without it, a run that crashes or is
            // killed BEFORE writing the completion artifact would leave a
            // `state=running` record with a dead orchestrator and no artifact,
            // wrongly pegging the singleton slot forever. With the pid recorded,
            // the in-flight filter + the reconcile tool can detect a dead
            // orchestrator and stop counting / re-classify the record.
            worker.record_orchestrator_pid(&jid, child.id());

            // Wait for the detached child with a wall-clock cap. Only a genuine
            // TIMEOUT kills the (process-group) tree; a normal exit leaves the
            // orchestrator's report dir intact. If the SERVER reloads here the
            // whole worker thread dies WITHOUT killing the child (no pipe, own
            // group), so the orchestrator keeps running — exactly the survival we
            // want; the poll fallback recovers the outcome from the report dir.
            let start = Instant::now();
            let timeout = Duration::from_secs(LAB_ORCHESTRATOR_TIMEOUT_SECS);
            let (success, timed_out) = loop {
                match child.try_wait() {
                    Ok(Some(status)) => break (status.success(), false),
                    Ok(None) => {
                        if start.elapsed() >= timeout {
                            kill_child_group(&mut child);
                            let _ = child.wait();
                            break (false, true);
                        }
                        std::thread::sleep(Duration::from_millis(200));
                    }
                    Err(e) => {
                        worker.finish_job(
                            &jid,
                            format!(
                                "# Live-lab run: {area} — error waiting on the orchestrator: {e}\n\n\
                                 (infrastructure error; inspect the log at `{}`.)",
                                log_path.display()
                            ),
                        );
                        return;
                    }
                }
            };

            let log_tail = tail_file(&log_path, 120).unwrap_or_default();
            let body = if timed_out {
                format!(
                    "# Live-lab run: {area} — TIMED OUT after {}s (orchestrator process group \
                     killed)\n\nEvidence (partial) in `{report_dir}`; orchestrator log: `{}`.\n\n\
                     _log tail:_\n{}",
                    timeout.as_secs(),
                    log_path.display(),
                    truncate_output(&log_tail, 60, 4000)
                )
            } else if dry_run {
                format!(
                    "# Live-lab run: {area} — DRY-RUN wiring check complete\n\n\
                     The orchestrator was launched with --dry-run, so skipped stages are NOT live \
                     evidence and must never be treated as a lab PASS. Exit status: {}. The launch \
                     → wait → capture → report path is verified; no triage is run for a dry run.\n\n\
                     _log tail:_\n{}",
                    if success { "0" } else { "non-zero" },
                    truncate_output(&log_tail, 60, 4000)
                )
            } else if success {
                format!(
                    "# Live-lab run: {area} — PASS\n\nThe orchestration completed successfully. \
                     Evidence in `{report_dir}` (verify the matrix row + per-stage results before \
                     trusting). No triage needed.\n\n_log tail:_\n{}",
                    truncate_output(&log_tail, 60, 4000)
                )
            } else if triage_on_failure {
                // Real run FAILED → feed the evidence to the rigid triage pipeline.
                let failure_context = format!(
                    "Live-lab orchestration for area '{area}' FAILED (orchestrator exited \
                     non-zero). Report dir the grounded agents can read: {report_dir}. \
                     Orchestrator log tail:\n{}",
                    truncate_output(&log_tail, 120, 9000)
                );
                let triage = worker.run_triage(&failure_context, max_steps);
                format!(
                    "# Live-lab run: {area} — FAIL → triage\n\nReport dir: `{report_dir}`\n\n{triage}"
                )
            } else {
                format!(
                    "# Live-lab run: {area} — FAIL (triage disabled)\n\n\
                     Report dir: `{report_dir}`\nOrchestrator log: `{}`\n\n\
                     `triage_on_failure=false` was set, so no external DeepSeek API call was made. \
                     Inspect the report locally, or call `deepseek_live_lab` manually after approving \
                     external triage of the selected failure context.\n\n_log tail:_\n{}",
                    log_path.display(),
                    truncate_output(&log_tail, 120, 9000)
                )
            };
            worker.finish_job(&jid, body);
        });

        ToolCallResult {
            content: text_content(started_msg),
            is_error: None,
        }
    }

    /// Execute one read-only agent tool locally. Always returns a string (errors
    /// are returned as text so the model can recover, not propagated up).
    fn dispatch_agent_tool(&self, name: &str, args: &Value) -> String {
        let result = match name {
            "read_file" => self.tool_read_file(args),
            "list_dir" => self.tool_list_dir(args),
            "grep" => self.tool_grep(args),
            "git" => self.tool_git(args),
            "utm_vm_status" => self.tool_utm_vm_status(),
            "lab_node_reachable" => self.tool_lab_node_reachable(args),
            "host_system_info" => self.tool_host_system_info(),
            "lab_run_status" => self.tool_lab_run_status(args),
            "lab_loop_journal" => self.tool_lab_loop_journal(args),
            "lab_inventory" => self.tool_lab_inventory(),
            "lab_jobs" => self.tool_lab_jobs(args),
            "lab_run_detail" => self.tool_lab_run_detail(args),
            "find_files" => self.tool_find_files(args),
            "host_disk_status" => self.tool_host_disk_status(),
            "lab_guest_exec" => self.tool_lab_guest_exec(args),
            "lab_job_log" => self.tool_lab_job_log(args),
            "lab_stage_log" => self.tool_lab_stage_log(args),
            "lab_report_grep" => self.tool_lab_report_grep(args),
            "lab_report_artifacts" => self.tool_lab_report_artifacts(args),
            "find_definition" => self.tool_find_definition(args),
            "find_references" => self.tool_find_references(args),
            "cargo_check" => self.tool_cargo_check(args),
            "cargo_test" => self.tool_cargo_test(args),
            other => Err(format!("unknown tool '{other}'")),
        };
        match result {
            Ok(s) => s,
            Err(e) => format!("ERROR: {e}"),
        }
    }

    /// Canonicalize `raw` joined under repo_root and assert the result stays
    /// inside the repo — rejecting `..` traversal AND symlink escape. Mirrors the
    /// repo_context read_safe pattern. The path must already exist.
    fn confine(&self, raw: &str) -> Result<PathBuf, String> {
        if raw.contains('\0') {
            return Err("path contains a NUL byte".into());
        }
        if Path::new(raw).is_absolute() {
            return Err("path must be repo-relative, not absolute".into());
        }
        let full = self.repo_root.join(raw);
        let canon = full
            .canonicalize()
            .map_err(|e| format!("cannot resolve '{raw}': {e}"))?;
        let root = self
            .repo_root
            .canonicalize()
            .map_err(|e| format!("cannot resolve repo root: {e}"))?;
        if !canon.starts_with(&root) {
            return Err(format!("path '{raw}' escapes the repository root"));
        }
        Ok(canon)
    }

    /// Confine an ALREADY-RESOLVED (possibly absolute) candidate path that the
    /// code built internally rather than received as a repo-relative arg — e.g.
    /// a stage-log path read out of a report dir's `stages.tsv`, or a fallback
    /// filename that may be a symlink. Canonicalize (resolving symlinks) and
    /// require repo-root containment, so an absolute path, a `..` escape, or a
    /// symlink to an out-of-tree target is rejected before any read.
    fn confine_resolved(&self, cand: &Path) -> Option<PathBuf> {
        let canon = cand.canonicalize().ok()?;
        let root = self.repo_root.canonicalize().ok()?;
        canon.starts_with(&root).then_some(canon)
    }

    fn tool_read_file(&self, args: &Value) -> Result<String, String> {
        let path = arg_str(args, "path").ok_or("missing 'path'")?;
        let max_bytes = args
            .get("max_bytes")
            .and_then(|v| v.as_u64())
            .map(|n| (n as usize).min(READ_FILE_HARD_MAX_BYTES))
            .unwrap_or(READ_FILE_DEFAULT_BYTES);
        let canon = self.confine(path)?;
        if !canon.is_file() {
            return Err(format!("'{path}' is not a regular file"));
        }
        let body = rustynet_mcp::read_file_capped(&canon, max_bytes)?;
        Ok(format!("# {path}\n\n{body}"))
    }

    fn tool_list_dir(&self, args: &Value) -> Result<String, String> {
        let path = arg_str(args, "path").unwrap_or(".");
        let canon = self.confine(path)?;
        if !canon.is_dir() {
            return Err(format!("'{path}' is not a directory"));
        }
        let mut entries: Vec<(String, &str, u64)> = Vec::new();
        let read = std::fs::read_dir(&canon).map_err(|e| format!("cannot list '{path}': {e}"))?;
        for entry in read.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            // symlink_metadata: report a symlink as a symlink, don't follow it.
            let meta = match entry.path().symlink_metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            let kind = if meta.file_type().is_symlink() {
                "symlink"
            } else if meta.is_dir() {
                "dir"
            } else {
                "file"
            };
            entries.push((name, kind, meta.len()));
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let mut out = format!("# {path}/ ({} entries)\n\n", entries.len());
        for (name, kind, size) in &entries {
            out.push_str(&format!("- {name} [{kind}] {size}B\n"));
        }
        Ok(out)
    }

    fn tool_grep(&self, args: &Value) -> Result<String, String> {
        let pattern = arg_str(args, "pattern").ok_or("missing 'pattern'")?;
        if pattern.is_empty() {
            return Err("'pattern' must not be empty".into());
        }
        let max_results = args
            .get("max_results")
            .and_then(|v| v.as_u64())
            .map(|n| n.clamp(1, 500) as usize)
            .unwrap_or(80);
        // Confine the optional search path; default to the whole repo (".").
        let search_rel = arg_str(args, "path").unwrap_or(".");
        let canon = self.confine(search_rel)?;
        // Pass the confined path as an absolute argv element so the search never
        // escapes the repo even though cwd=repo_root.
        let canon_str = canon.to_string_lossy().to_string();
        // Optional surrounding-context lines (rg/grep -C N), so the agent can see
        // the code around a match and ground claims more precisely.
        let context = args
            .get("context")
            .and_then(|v| v.as_u64())
            .map(|n| n.clamp(0, 10))
            .unwrap_or(0);
        let context_str = context.to_string();

        // Prefer ripgrep; fall back to grep -rn. argv-only: the pattern is a
        // separate argument and is NEVER interpolated into a shell string.
        let (program, argv): (&str, Vec<&str>) = if which("rg") {
            // Ignore any ambient RIPGREP_CONFIG_PATH that could inject a
            // preprocessor (`--pre`) command — keep grep read-only.
            let mut v = vec![
                "--no-config",
                "--no-heading",
                "--line-number",
                "--color=never",
                "--max-count",
                "200",
            ];
            if context > 0 {
                v.push("-C");
                v.push(context_str.as_str());
            }
            v.extend(["-e", pattern, "--", canon_str.as_str()]);
            ("rg", v)
        } else {
            let mut v = vec!["-rn", "--color=never"];
            if context > 0 {
                v.push("-C");
                v.push(context_str.as_str());
            }
            v.extend(["-e", pattern, "--", canon_str.as_str()]);
            ("grep", v)
        };
        let outcome = run_with_timeout(
            program,
            &argv,
            &self.repo_root,
            &[],
            Duration::from_secs(SUBPROC_TIMEOUT_SECS),
        )?;
        // grep/rg exit 1 on "no matches" — that is not an error here.
        let lines: Vec<&str> = outcome
            .stdout
            .lines()
            .take(max_results)
            .map(strip_repo_prefix_in_line(&self.repo_root))
            .collect();
        if lines.is_empty() {
            if !outcome.success && outcome.code != Some(1) {
                return Err(format!(
                    "{program} failed (exit {:?}): {}",
                    outcome.code,
                    outcome.stderr.trim()
                ));
            }
            return Ok(format!("# grep \"{pattern}\"\n\n(no matches)\n"));
        }
        Ok(format!(
            "# grep \"{pattern}\" ({} match line(s), via {program})\n\n{}\n",
            lines.len(),
            lines.join("\n")
        ))
    }

    fn tool_git(&self, args: &Value) -> Result<String, String> {
        let raw = args
            .get("args")
            .and_then(|v| v.as_array())
            .ok_or("missing 'args' (array of strings)")?;
        let parts: Vec<String> = raw
            .iter()
            .map(|v| v.as_str().map(String::from))
            .collect::<Option<Vec<_>>>()
            .ok_or("'args' must be an array of strings")?;
        let sub = parts.first().map(String::as_str).unwrap_or("");
        // Allowlist read-only subcommands ONLY. Anything that can mutate the
        // working tree, index, refs, or remote is rejected.
        const READ_ONLY_GIT: &[&str] = &[
            "log",
            "show",
            "diff",
            "status",
            "blame",
            "rev-parse",
            "ls-files",
            "cat-file",
            "describe",
            "shortlog",
            "branch",
            "tag",
            "rev-list",
            "ls-tree",
            "grep",
            "for-each-ref",
        ];
        if !READ_ONLY_GIT.contains(&sub) {
            return Err(format!(
                "git subcommand '{sub}' is not in the read-only allowlist ({})",
                READ_ONLY_GIT.join(", ")
            ));
        }
        // Defensive: even allowlisted subcommands must not be coerced into a
        // write via flags like `branch -d`, `tag -d`, `branch -m`, `branch -f`.
        if matches!(sub, "branch" | "tag")
            && parts.iter().skip(1).any(|a| {
                matches!(
                    a.as_str(),
                    "-d" | "-D"
                        | "-m"
                        | "-M"
                        | "-f"
                        | "--delete"
                        | "--move"
                        | "--force"
                        | "--create-reflog"
                )
            })
        {
            return Err(format!(
                "git {sub} write/delete flags are not allowed (read-only)"
            ));
        }
        // Reject flags that can WRITE a file or EXEC a command even inside an
        // allowlisted read-only subcommand: `git diff --output=F` writes the
        // diff to an arbitrary path; `git grep -O<cmd>` / `--open-files-in-pager`
        // and `--ext-diff` run an external command; `cat-file --textconv` /
        // `--filters` invoke .gitattributes-configured textconv / smudge filters
        // (also a command exec). These are the read-only-contract escape hatches
        // the subcommand allowlist alone misses.
        if parts.iter().skip(1).any(|a| {
            a == "--output"
                || a.starts_with("--output=")
                || a == "--open-files-in-pager"
                || a.starts_with("--open-files-in-pager=")
                || a.starts_with("-O")
                || a == "--ext-diff"
                || a == "--textconv"
                || a == "--filters"
        }) {
            return Err(
                "git flags that write a file or exec a command are not allowed (read-only)".into(),
            );
        }
        let argv: Vec<&str> = parts.iter().map(String::as_str).collect();
        // Hardened, deterministic git environment: never invoke a pager, ignore
        // ambient global/system gitconfig and GIT_CONFIG_PARAMETERS, and never
        // prompt — so a stray pager / alias / filter in the operator's
        // environment cannot turn a read-only inspection into a command exec.
        let git_env: &[(&str, &str)] = &[
            ("GIT_PAGER", "cat"),
            ("PAGER", "cat"),
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
            ("GIT_CONFIG_SYSTEM", "/dev/null"),
            ("GIT_CONFIG_PARAMETERS", ""),
            ("GIT_TERMINAL_PROMPT", "0"),
        ];
        let outcome = run_with_timeout(
            "git",
            &argv,
            &self.repo_root,
            git_env,
            Duration::from_secs(SUBPROC_TIMEOUT_SECS),
        )?;
        let mut out = format!("# git {}\n\n", parts.join(" "));
        let stdout = outcome.stdout.trim();
        if !stdout.is_empty() {
            out.push_str(&format!("```\n{stdout}\n```\n"));
        }
        let stderr = outcome.stderr.trim();
        if !stderr.is_empty() {
            out.push_str(&format!(
                "\n_stderr:_ {}\n",
                truncate_output(stderr, 10, 1000)
            ));
        }
        if stdout.is_empty() && stderr.is_empty() {
            out.push_str("(no output)\n");
        }
        Ok(out)
    }

    fn tool_utm_vm_status(&self) -> Result<String, String> {
        let utmctl = utmctl_path();
        let outcome = run_with_timeout(
            &utmctl,
            &["list"],
            &self.repo_root,
            &[],
            Duration::from_secs(SUBPROC_TIMEOUT_SECS),
        )?;
        if !outcome.success {
            return Err(format!(
                "utmctl list failed: {}. (Set RUSTYNET_UTMCTL_PATH if UTM is elsewhere.)",
                outcome.stderr.trim()
            ));
        }
        let mut out = String::from("# UTM VMs (utmctl list)\n\n| status | name |\n|---|---|\n");
        let mut rows = 0;
        for line in outcome.stdout.lines() {
            let t = line.trim();
            if t.is_empty() || t.starts_with("UUID") {
                continue;
            }
            // Columns: UUID  Status  Name.
            let Some(status) = t.split_whitespace().nth(1) else {
                continue;
            };
            let name = match t.find(status) {
                Some(i) => t[i + status.len()..].trim(),
                None => continue,
            };
            out.push_str(&format!("| {status} | {name} |\n"));
            rows += 1;
        }
        if rows == 0 {
            out.push_str("| (none) | |\n");
        }
        Ok(out)
    }

    fn tool_lab_node_reachable(&self, args: &Value) -> Result<String, String> {
        let host = arg_str(args, "host").ok_or("missing 'host'")?.trim();
        if !is_valid_host(host) {
            return Err(format!(
                "invalid host '{host}': must be an IP or simple hostname (letters, digits, '.', '-')"
            ));
        }
        let port = args
            .get("port")
            .and_then(|v| v.as_u64())
            .map(|p| p.clamp(1, 65535) as u16)
            .unwrap_or(22);
        // Resolve and probe via TcpStream::connect_timeout. ToSocketAddrs does
        // DNS resolution for a hostname; for a bare IP it is a no-op parse.
        let target = format!("{host}:{port}");
        let mut addrs = match target.to_socket_addrs() {
            Ok(a) => a,
            Err(e) => {
                return Ok(format!(
                    "# Reachability {host}:{port}\n\n- resolved: NO ({e})\n- reachable: false\n"
                ));
            }
        };
        let Some(addr) = addrs.next() else {
            return Ok(format!(
                "# Reachability {host}:{port}\n\n- resolved: NO (no addresses)\n- reachable: false\n"
            ));
        };
        let reachable = TcpStream::connect_timeout(&addr, Duration::from_secs(3)).is_ok();
        Ok(format!(
            "# Reachability {host}:{port}\n\n- resolved: {addr}\n- TCP reachable: {reachable}\n"
        ))
    }

    fn tool_host_system_info(&self) -> Result<String, String> {
        let mut out = String::from("# Host system info\n\n");
        out.push_str(&format!(
            "- os (compile-time): {}\n- arch (compile-time): {}\n",
            std::env::consts::OS,
            std::env::consts::ARCH
        ));
        // uname -a, argv-only. Best-effort: absence is informative, not fatal.
        match run_with_timeout(
            "uname",
            &["-a"],
            &self.repo_root,
            &[],
            Duration::from_secs(SUBPROC_TIMEOUT_SECS),
        ) {
            Ok(o) if o.success => out.push_str(&format!("- uname -a: `{}`\n", o.stdout.trim())),
            Ok(o) => out.push_str(&format!("- uname -a: (failed: {})\n", o.stderr.trim())),
            Err(e) => out.push_str(&format!("- uname -a: (unavailable: {e})\n")),
        }
        Ok(out)
    }

    fn tool_lab_run_status(&self, args: &Value) -> Result<String, String> {
        let limit = args
            .get("limit")
            .and_then(|v| v.as_u64())
            .map(|n| n.clamp(1, 50) as usize)
            .unwrap_or(10);
        let path = self
            .repo_root
            .join("documents/operations/live_lab_run_matrix.csv");
        if !path.is_file() {
            return Ok("# live-lab run matrix\n\n(not found)\n".to_string());
        }
        let body = rustynet_mcp::read_file_capped(&path, 8_000_000)?;
        let mut lines = body.lines();
        let header = parse_csv_line(lines.next().unwrap_or(""));
        let col = |name: &str| header.iter().position(|c| c.as_str() == name);
        let (i_started, i_commit, i_overall, i_failed, i_two_hop, i_relay, i_report_dir) = (
            col("run_started_utc"),
            col("git_commit"),
            col("overall_result"),
            col("first_failed_stage"),
            col("linux_stage_two_hop"),
            col("linux_stage_relay_service_lifecycle"),
            col("report_dir"),
        );
        let rows: Vec<&str> = lines.filter(|l| !l.trim().is_empty()).collect();
        let start = rows.len().saturating_sub(limit);
        let mut out = format!(
            "# Live-lab run matrix — last {} of {} runs\n\n",
            rows.len().min(limit),
            rows.len()
        );
        // report_dir is surfaced so it can be passed to lab_run_detail /
        // lab_stage_log / lab_report_grep / lab_report_artifacts.
        out.push_str(
            "| started | commit | overall | first_failed | two_hop | relay_svc | report_dir |\n",
        );
        out.push_str("|---|---|---|---|---|---|---|\n");
        for row in &rows[start..] {
            let f = parse_csv_line(row);
            let g = |oi: Option<usize>| -> String {
                oi.and_then(|i| f.get(i)).cloned().unwrap_or_default()
            };
            let commit: String = g(i_commit).chars().take(8).collect();
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} |\n",
                g(i_started),
                commit,
                g(i_overall),
                g(i_failed),
                g(i_two_hop),
                g(i_relay),
                g(i_report_dir),
            ));
        }
        Ok(out)
    }

    fn tool_lab_loop_journal(&self, args: &Value) -> Result<String, String> {
        let limit = args
            .get("limit")
            .and_then(|v| v.as_u64())
            .map(|n| n.clamp(1, 100) as usize)
            .unwrap_or(15);
        let path = self.repo_root.join("state/mcp-loop-journal.jsonl");
        if !path.is_file() {
            return Ok(
                "# loop journal\n\n(no journal at state/mcp-loop-journal.jsonl yet)\n".to_string(),
            );
        }
        let body = rustynet_mcp::read_file_capped(&path, 8_000_000)?;
        let lines: Vec<&str> = body.lines().filter(|l| !l.trim().is_empty()).collect();
        let start = lines.len().saturating_sub(limit);
        let mut out = format!(
            "# Loop journal — last {} of {} notes (the lab loop's durable findings)\n\n",
            lines.len().min(limit),
            lines.len()
        );
        for line in &lines[start..] {
            match serde_json::from_str::<Value>(line) {
                Ok(v) => {
                    let note = v.get("note").and_then(|n| n.as_str()).unwrap_or(line);
                    let status = v.get("status").and_then(|s| s.as_str()).unwrap_or("");
                    let iter = v.get("iteration").and_then(|i| i.as_u64());
                    let hdr = match (iter, status) {
                        (Some(i), s) if !s.is_empty() => format!("- [#{i} {s}] "),
                        (Some(i), _) => format!("- [#{i}] "),
                        (None, s) if !s.is_empty() => format!("- [{s}] "),
                        _ => "- ".to_string(),
                    };
                    out.push_str(&hdr);
                    out.push_str(&truncate_output(note, 12, 1200));
                    out.push('\n');
                }
                Err(_) => out.push_str(&format!("- {}\n", truncate_output(line, 4, 600))),
            }
        }
        Ok(out)
    }

    /// Summarize the UTM VM lab inventory JSON: per node alias, IP(s), role,
    /// OS/platform, and ssh user. Pure file read; the inventory is a tracked
    /// repo file, so confine its repo-relative path before reading.
    fn tool_lab_inventory(&self) -> Result<String, String> {
        let canon = self.confine(LAB_INVENTORY_PATH)?;
        if !canon.is_file() {
            return Ok(format!(
                "# lab inventory\n\n(not found at {LAB_INVENTORY_PATH})\n"
            ));
        }
        let body = rustynet_mcp::read_file_capped(&canon, 4 * 1024 * 1024)?;
        let inv: Value = serde_json::from_str(&body)
            .map_err(|e| format!("invalid inventory JSON at {LAB_INVENTORY_PATH}: {e}"))?;
        let entries = inv
            .get("entries")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let mut out = format!(
            "# Lab inventory ({} node(s)) — {LAB_INVENTORY_PATH}\n\n\
             | alias | platform | os | role | ssh_user | mesh_ip | ips |\n\
             |---|---|---|---|---|---|---|\n",
            entries.len()
        );
        for e in &entries {
            let g = |k: &str| e.get(k).and_then(|v| v.as_str()).unwrap_or("");
            // Linux entries have no `platform` field; surface them as 'linux'.
            let platform = if g("platform").is_empty() {
                "linux"
            } else {
                g("platform")
            };
            // Prefer the multi-IP list; fall back to the single known IP.
            let ips = match e.get("live_ips").and_then(|v| v.as_array()) {
                Some(arr) if !arr.is_empty() => arr
                    .iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(" "),
                _ => {
                    let single = if !g("last_known_ip").is_empty() {
                        g("last_known_ip")
                    } else {
                        g("ssh_target")
                    };
                    single.to_string()
                }
            };
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} |\n",
                g("alias"),
                platform,
                g("os"),
                g("lab_role"),
                g("ssh_user"),
                g("mesh_ip"),
                truncate_output(&ips, 1, 200).replace('\n', " "),
            ));
        }
        out.push_str(
            "\n_Credentials (ssh passwords/keys) are intentionally omitted from this view._\n",
        );
        Ok(out)
    }

    /// List the most-recent live-lab background job records under
    /// `state/mcp-jobs/`, newest first, with job_id + state + overall_result +
    /// mode. Pure file read; if the dir is absent, say so and return Ok.
    fn tool_lab_jobs(&self, args: &Value) -> Result<String, String> {
        let limit = args
            .get("limit")
            .and_then(|v| v.as_u64())
            .map(|n| n.clamp(1, 50) as usize)
            .unwrap_or(10);
        let jobs_dir = self.repo_root.join("state/mcp-jobs");
        if !jobs_dir.is_dir() {
            return Ok("# live-lab jobs\n\n(no jobs dir at state/mcp-jobs/ yet)\n".to_string());
        }
        // Collect (mtime, path) for every .json job record, newest first.
        let mut records: Vec<(SystemTime, PathBuf)> = Vec::new();
        let read =
            std::fs::read_dir(&jobs_dir).map_err(|e| format!("cannot list jobs dir: {e}"))?;
        for entry in read.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                let mtime = entry
                    .metadata()
                    .and_then(|m| m.modified())
                    .unwrap_or(UNIX_EPOCH);
                records.push((mtime, path));
            }
        }
        records.sort_by_key(|record| std::cmp::Reverse(record.0));
        let total = records.len();
        // report_dir is surfaced so the model can pass it to lab_run_detail /
        // lab_stage_log / lab_report_grep / lab_report_artifacts (and the job_id
        // to lab_job_log).
        let mut out = format!(
            "# Live-lab jobs — newest {} of {total} (state/mcp-jobs/)\n\n\
             | job_id | state | overall_result | mode | report_dir |\n|---|---|---|---|---|\n",
            total.min(limit)
        );
        for (_, path) in records.iter().take(limit) {
            let Ok(s) = std::fs::read_to_string(path) else {
                continue;
            };
            let Ok(rec) = serde_json::from_str::<Value>(&s) else {
                continue;
            };
            let g = |k: &str| {
                rec.get(k)
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string()
            };
            let job_id = g("job_id");
            let mode = g("mode");
            let report_dir = g("report_dir");
            // Derive completion state + overall_result from the run's report dir
            // (read-only): report_state.json is authoritative if present.
            let (state, overall) = self.job_state_summary(&rec);
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                if job_id.is_empty() { "?" } else { &job_id },
                state,
                overall,
                if mode.is_empty() { "?" } else { &mode },
                if report_dir.is_empty() {
                    "-"
                } else {
                    &report_dir
                },
            ));
        }
        if total == 0 {
            out.push_str("| (none) | | | | |\n");
        }
        Ok(out)
    }

    /// Read-only completion summary for one job record: (state, overall_result).
    /// `report_state.json` (run_complete/run_passed) is authoritative; the matrix
    /// row supplies the human-readable overall_result. Never spawns a process or
    /// probes a pid — this is a pure file read.
    fn job_state_summary(&self, rec: &Value) -> (String, String) {
        let report_dir = rec.get("report_dir").and_then(|v| v.as_str());
        let Some(report_dir) = report_dir else {
            return ("unknown".into(), "-".into());
        };
        // Confine the recorded report dir under the repo before reading.
        let Ok(canon) = self.confine(report_dir) else {
            return ("unknown (report dir escapes repo)".into(), "-".into());
        };
        let report_state = std::fs::read_to_string(canon.join("state/report_state.json"))
            .ok()
            .and_then(|s| serde_json::from_str::<Value>(&s).ok());
        let state = match &report_state {
            Some(rs)
                if rs
                    .get("run_complete")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false) =>
            {
                if rs
                    .get("run_passed")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                {
                    "passed".to_string()
                } else {
                    "failed".to_string()
                }
            }
            Some(_) => "ended (no run completion)".to_string(),
            None => "ended (no completion record)".to_string(),
        };
        // overall_result lives in the per-run matrix row CSV.
        let overall = self
            .matrix_row_field(&canon, "overall_result")
            .unwrap_or_else(|| "-".to_string());
        (state, overall)
    }

    /// Read a single field from a run's `state/live_lab_run_matrix_row.csv`
    /// (header line + one data line). Returns None when absent/malformed.
    fn matrix_row_field(&self, report_dir: &Path, field: &str) -> Option<String> {
        let s =
            std::fs::read_to_string(report_dir.join("state/live_lab_run_matrix_row.csv")).ok()?;
        let mut lines = s.lines();
        let header = parse_csv_line(lines.next()?);
        let row = parse_csv_line(lines.next()?);
        let idx = header.iter().position(|c| c == field)?;
        row.get(idx).map(|v| v.trim().to_string())
    }

    /// Summarize one live-lab run report directory: per-stage status from
    /// `state/stages.tsv`, validator pass/fail from `validator_results.json`,
    /// and the matrix-row overall_result / first_failed_stage. Pure file read;
    /// the report_dir is confined under the repo root.
    fn tool_lab_run_detail(&self, args: &Value) -> Result<String, String> {
        let report_dir = arg_str(args, "report_dir").ok_or("missing 'report_dir'")?;
        let canon = self.confine(report_dir)?;
        if !canon.is_dir() {
            return Err(format!("'{report_dir}' is not a directory"));
        }
        let mut out = format!("# Live-lab run detail — {report_dir}\n\n");

        // Overall verdict from the matrix row.
        let overall = self
            .matrix_row_field(&canon, "overall_result")
            .unwrap_or_else(|| "(no matrix row)".to_string());
        let first_failed = self
            .matrix_row_field(&canon, "first_failed_stage")
            .unwrap_or_default();
        out.push_str(&format!("- overall_result: **{overall}**\n"));
        if !first_failed.is_empty() {
            out.push_str(&format!("- first_failed_stage: `{first_failed}`\n"));
        }

        // Per-stage status from stages.tsv (col0 = name, col2 = status).
        out.push_str("\n## Stages (state/stages.tsv)\n\n");
        match std::fs::read_to_string(canon.join("state/stages.tsv")) {
            Ok(body) => {
                let mut rows = 0;
                for line in body.lines() {
                    let cols: Vec<&str> = line.split('\t').collect();
                    let (Some(name), Some(status)) = (cols.first(), cols.get(2)) else {
                        continue;
                    };
                    if name.trim().is_empty() {
                        continue;
                    }
                    out.push_str(&format!("- {} → {}\n", name.trim(), status.trim()));
                    rows += 1;
                }
                if rows == 0 {
                    out.push_str("(no stage rows)\n");
                }
            }
            Err(_) => out.push_str("(no state/stages.tsv)\n"),
        }

        // Validator results: node → array of {op, passed, summary}.
        out.push_str("\n## Validators (validator_results.json)\n\n");
        match std::fs::read_to_string(canon.join("validator_results.json")) {
            Ok(body) => match serde_json::from_str::<Value>(&body) {
                Ok(Value::Object(map)) => {
                    for (node, results) in &map {
                        let Some(arr) = results.as_array() else {
                            continue;
                        };
                        let parts: Vec<String> = arr
                            .iter()
                            .map(|r| {
                                let op = r.get("op").and_then(|v| v.as_str()).unwrap_or("?");
                                let passed =
                                    r.get("passed").and_then(|v| v.as_bool()).unwrap_or(false);
                                format!("{op}={}", if passed { "pass" } else { "FAIL" })
                            })
                            .collect();
                        out.push_str(&format!("- {node}: {}\n", parts.join(", ")));
                    }
                }
                _ => out.push_str("(validator_results.json is not the expected object shape)\n"),
            },
            Err(_) => out.push_str("(no validator_results.json)\n"),
        }
        Ok(out)
    }

    /// Find repo files whose PATH matches the glob/substring `pattern`. Prefers
    /// `rg --files -g <pattern>` (argv-only — the pattern is never interpolated
    /// into a shell string); falls back to `git ls-files` filtered by substring.
    /// Results are repo-relative and bounded.
    fn tool_find_files(&self, args: &Value) -> Result<String, String> {
        let pattern = arg_str(args, "pattern").ok_or("missing 'pattern'")?;
        if pattern.is_empty() {
            return Err("'pattern' must not be empty".into());
        }
        if pattern.contains('\0') {
            return Err("pattern contains a NUL byte".into());
        }
        let limit = args
            .get("limit")
            .and_then(|v| v.as_u64())
            .map(|n| n.clamp(1, 1000) as usize)
            .unwrap_or(100);

        let (lines, via): (Vec<String>, &str) = if which("rg") {
            // argv-only: pattern is a separate `-g` glob argument, never a shell
            // string. --no-config blocks an ambient RIPGREP_CONFIG_PATH preprocessor.
            let outcome = run_with_timeout(
                "rg",
                &["--no-config", "--files", "--color=never", "-g", pattern],
                &self.repo_root,
                &[],
                Duration::from_secs(SUBPROC_TIMEOUT_SECS),
            )?;
            // rg --files exits 1 when the glob matches nothing — not an error here.
            if !outcome.success && outcome.code != Some(1) {
                return Err(format!(
                    "rg --files failed (exit {:?}): {}",
                    outcome.code,
                    outcome.stderr.trim()
                ));
            }
            let lines = outcome
                .stdout
                .lines()
                .map(strip_repo_prefix_in_line(&self.repo_root))
                .map(String::from)
                .collect();
            (lines, "rg --files")
        } else {
            // Fallback: git ls-files (every tracked path), filtered by substring.
            // The pattern is treated as a literal substring, never a shell token.
            let outcome = run_with_timeout(
                "git",
                &["ls-files"],
                &self.repo_root,
                &[
                    ("GIT_PAGER", "cat"),
                    ("PAGER", "cat"),
                    ("GIT_CONFIG_GLOBAL", "/dev/null"),
                    ("GIT_CONFIG_SYSTEM", "/dev/null"),
                    ("GIT_CONFIG_PARAMETERS", ""),
                    ("GIT_TERMINAL_PROMPT", "0"),
                ],
                Duration::from_secs(SUBPROC_TIMEOUT_SECS),
            )?;
            if !outcome.success {
                return Err(format!(
                    "git ls-files failed (exit {:?}): {}",
                    outcome.code,
                    outcome.stderr.trim()
                ));
            }
            let lines = outcome
                .stdout
                .lines()
                .filter(|l| l.contains(pattern))
                .map(String::from)
                .collect();
            (lines, "git ls-files (substring)")
        };

        let shown: Vec<&String> = lines.iter().take(limit).collect();
        if shown.is_empty() {
            return Ok(format!("# find_files \"{pattern}\"\n\n(no matches)\n"));
        }
        let mut out = format!(
            "# find_files \"{pattern}\" ({} match(es){}, via {via})\n\n",
            shown.len(),
            if lines.len() > shown.len() {
                format!(" of {}", lines.len())
            } else {
                String::new()
            },
        );
        for line in shown {
            out.push_str(&format!("- {line}\n"));
        }
        Ok(out)
    }

    /// Read-only host disk usage for the repo filesystem and `/` via `df -h`
    /// (argv-only). Never writes.
    fn tool_host_disk_status(&self) -> Result<String, String> {
        let mut out = String::from("# Host disk status\n\n");
        // df -h <repo_root> and df -h / — argv-only, best-effort.
        for (label, target) in [
            ("repo volume", self.repo_root.to_string_lossy().to_string()),
            ("root (/)", "/".to_string()),
        ] {
            out.push_str(&format!("## {label}\n"));
            match run_with_timeout(
                "df",
                &["-h", target.as_str()],
                &self.repo_root,
                &[],
                Duration::from_secs(SUBPROC_TIMEOUT_SECS),
            ) {
                Ok(o) if o.success => out.push_str(&format!("```\n{}\n```\n", o.stdout.trim())),
                Ok(o) => out.push_str(&format!("(df failed: {})\n", o.stderr.trim())),
                Err(e) => out.push_str(&format!("(df unavailable: {e})\n")),
            }
        }
        Ok(out)
    }

    /// Run ONE of four FIXED read-only diagnostic commands inside a named,
    /// running Linux UTM guest via `utmctl exec`. The command is selected by the
    /// `check` enum and is NOT caller-controlled — there is no arbitrary exec.
    /// Fails closed if the alias is invalid, unknown, not running, not Linux, or
    /// utmctl is unavailable.
    fn tool_lab_guest_exec(&self, args: &Value) -> Result<String, String> {
        let vm_alias = arg_str(args, "vm_alias")
            .ok_or("missing 'vm_alias'")?
            .trim();
        // Strict allowlist: ASCII alphanumeric, '-', '_' only. Rejects path
        // traversal, shell metacharacters, whitespace, everything else. The alias
        // only ever reaches utmctl as a separate argv element, but validate hard.
        if vm_alias.is_empty()
            || vm_alias.len() > 64
            || !vm_alias
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(format!(
                "invalid vm_alias '{vm_alias}': only ASCII letters, digits, '-' and '_' allowed"
            ));
        }
        let check = arg_str(args, "check").ok_or("missing 'check'")?.trim();
        let conn = self
            .lab_guest_conn(vm_alias)?
            .ok_or_else(|| format!("unknown vm_alias '{vm_alias}' (not in inventory)"))?;

        match conn.platform.as_str() {
            "linux" => {
                // Linux: utmctl exec — out-of-band, works even if SSH is wedged.
                let cmd = linux_guest_cmd(check).ok_or_else(|| {
                    format!("invalid check '{check}' for linux: network|routes|dns|service|ports|firewall")
                })?;
                let utm_name = conn
                    .utm_name
                    .as_deref()
                    .ok_or("linux guest has no controller.utm_name in inventory")?;
                let utmctl = utmctl_path();
                let power = self.utm_power_status(&utmctl, utm_name)?;
                if power.as_deref() != Some("started") {
                    return Err(format!(
                        "VM '{vm_alias}' (utm_name={utm_name}) is '{}', not started",
                        power.as_deref().unwrap_or("unknown")
                    ));
                }
                let mut argv: Vec<&str> = vec!["exec", utm_name, "--cmd"];
                argv.extend_from_slice(cmd);
                let outcome = run_with_timeout(
                    &utmctl,
                    &argv,
                    &self.repo_root,
                    &[],
                    Duration::from_secs(SUBPROC_TIMEOUT_SECS),
                )?;
                Ok(format_guest_output(
                    vm_alias,
                    check,
                    "linux",
                    &cmd.join(" "),
                    &outcome.stdout,
                    &outcome.stderr,
                ))
            }
            platform @ ("macos" | "windows") => {
                // macOS/Windows: no utmctl exec → SSH. Fixed (non-caller) command;
                // password from the inventory passed via the SSHPASS env var, never
                // in argv or logs. PubkeyAuthentication=no so we don't leak a key.
                let remote = ssh_guest_cmd(platform, check).ok_or_else(|| {
                    format!("invalid check '{check}' for {platform}: network|routes|dns|service|ports|firewall")
                })?;
                let target = conn
                    .ssh_target
                    .as_deref()
                    .ok_or("no ssh_target/last_known_ip in inventory for this guest")?;
                if !is_valid_host(target) {
                    return Err(format!("invalid ssh_target '{target}' in inventory"));
                }
                let user = conn
                    .ssh_user
                    .as_deref()
                    .ok_or("no ssh_user in inventory for this guest")?;
                if user.is_empty()
                    || user.len() > 64
                    || !user
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
                {
                    return Err(format!("invalid ssh_user '{user}' in inventory"));
                }
                let pw = conn
                    .ssh_password
                    .as_deref()
                    .ok_or("no ssh_password in inventory for this guest (SSH exec needs it)")?;
                if !which("sshpass") {
                    return Err(
                        "sshpass not on PATH — required for macOS/Windows guest SSH (e.g. brew install sshpass)".into(),
                    );
                }
                let userhost = format!("{user}@{target}");
                let env: Vec<(&str, &str)> = vec![("SSHPASS", pw)];
                let argv: Vec<&str> = vec![
                    "-e",
                    "ssh",
                    "-o",
                    "StrictHostKeyChecking=accept-new",
                    "-o",
                    "ConnectTimeout=10",
                    "-o",
                    "PreferredAuthentications=password",
                    "-o",
                    "PubkeyAuthentication=no",
                    &userhost,
                    remote,
                ];
                let outcome = run_with_timeout(
                    "sshpass",
                    &argv,
                    &self.repo_root,
                    &env,
                    Duration::from_secs(GUEST_SSH_TIMEOUT_SECS),
                )?;
                Ok(format_guest_output(
                    vm_alias,
                    check,
                    platform,
                    remote,
                    &outcome.stdout,
                    &outcome.stderr,
                ))
            }
            other => Err(format!(
                "vm_alias '{vm_alias}' has unknown platform '{other}'"
            )),
        }
    }

    /// Resolve an inventory alias → its connection details (platform, utm_name,
    /// ssh_target/user/password). Linux entries have no `platform` field → "linux".
    /// Returns Ok(None) when the alias is absent. The inventory path is confined;
    /// the ssh_password (a pre-existing lab-inventory field) is only ever read here
    /// and handed to sshpass via the SSHPASS env var — never logged or returned.
    fn lab_guest_conn(&self, alias: &str) -> Result<Option<GuestConn>, String> {
        let canon = self.confine(LAB_INVENTORY_PATH)?;
        let body = rustynet_mcp::read_file_capped(&canon, 4 * 1024 * 1024)?;
        let inv: Value =
            serde_json::from_str(&body).map_err(|e| format!("invalid inventory JSON: {e}"))?;
        let Some(entries) = inv.get("entries").and_then(|v| v.as_array()) else {
            return Ok(None);
        };
        for e in entries {
            if e.get("alias").and_then(|v| v.as_str()) != Some(alias) {
                continue;
            }
            let s = |k: &str| e.get(k).and_then(|v| v.as_str()).map(String::from);
            let platform = e
                .get("platform")
                .and_then(|v| v.as_str())
                .filter(|p| !p.is_empty())
                .unwrap_or("linux")
                .to_string();
            let ssh_target = s("ssh_target").or_else(|| s("last_known_ip")).or_else(|| {
                e.get("live_ips")
                    .and_then(|v| v.as_array())
                    .and_then(|a| a.first())
                    .and_then(|v| v.as_str())
                    .map(String::from)
            });
            return Ok(Some(GuestConn {
                platform,
                utm_name: e
                    .get("controller")
                    .and_then(|c| c.get("utm_name"))
                    .and_then(|v| v.as_str())
                    .map(String::from),
                ssh_target,
                ssh_user: s("ssh_user"),
                ssh_password: s("ssh_password"),
            }));
        }
        Ok(None)
    }

    /// utmctl power status (started/stopped/...) for one utm_name. Read-only —
    /// runs `utmctl list` and matches the row. Mirrors lab_state's parser.
    fn utm_power_status(&self, utmctl: &str, utm_name: &str) -> Result<Option<String>, String> {
        let outcome = run_with_timeout(
            utmctl,
            &["list"],
            &self.repo_root,
            &[],
            Duration::from_secs(SUBPROC_TIMEOUT_SECS),
        )
        .map_err(|e| {
            format!(
                "cannot run utmctl ({utmctl}): {e}. Set RUSTYNET_UTMCTL_PATH if UTM is elsewhere."
            )
        })?;
        if !outcome.success {
            return Err(format!("utmctl list failed: {}", outcome.stderr.trim()));
        }
        for line in outcome.stdout.lines() {
            let t = line.trim();
            if t.is_empty() || t.starts_with("UUID") {
                continue;
            }
            // Columns: UUID  Status  Name.
            let Some(status) = t.split_whitespace().nth(1) else {
                continue;
            };
            let Some(i) = t.find(status) else {
                continue;
            };
            let name = t[i + status.len()..].trim();
            if name == utm_name {
                return Ok(Some(status.to_string()));
            }
        }
        Ok(None)
    }

    /// Read the tail of (or, with `grep`, the matching lines from) a background
    /// job's combined log at `state/mcp-jobs/<job_id>.log` — where the
    /// orchestrator/setup-stage errors (bootstrap_hosts, cleanup_hosts, the
    /// offline cargo build error, SSH errors) live. Mirrors lab_state's job-log
    /// path convention (JOBS_SUBDIR + `<job_id>.log`). Read-only; an absent log
    /// is reported, not an error.
    fn tool_lab_job_log(&self, args: &Value) -> Result<String, String> {
        let job_id = arg_str(args, "job_id").ok_or("missing 'job_id'")?.trim();
        // Job-id charset: ASCII alphanumeric, '-', '_' ONLY. Rejects '.' and '/'
        // (so '../etc/passwd' / 'a/b' can never form a path), shell metachars,
        // whitespace — validated BEFORE the path is built. Job ids look like
        // `ll-<millis>-<pid>-<seq>`, well inside this charset.
        if job_id.is_empty()
            || job_id.len() > 128
            || !job_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(format!(
                "invalid job_id '{job_id}': only ASCII letters, digits, '-' and '_' allowed"
            ));
        }
        let tail = args
            .get("tail")
            .and_then(|v| v.as_u64())
            .map(|n| n.clamp(1, 2000) as usize)
            .unwrap_or(200);
        // Build under JOBS_SUBDIR then confine (defence in depth: confine also
        // rejects traversal/absolute/NUL and requires the file to exist).
        let rel = format!("{JOBS_SUBDIR}/{job_id}.log");
        let canon = match self.confine(&rel) {
            Ok(c) => c,
            // confine fails when the file is absent — that is not an error here.
            Err(_) => {
                return Ok(format!(
                    "# job log {job_id}\n\n(no log at {rel} — unknown/expired job, or it never wrote one)\n"
                ));
            }
        };
        if !canon.is_file() {
            return Ok(format!("# job log {job_id}\n\n(no log at {rel})\n"));
        }
        // Optional grep filter: substring, IN-PROCESS — never a shell/regex.
        if let Some(pattern) = arg_str(args, "grep") {
            if pattern.contains('\0') {
                return Err("grep pattern contains a NUL byte".into());
            }
            if pattern.is_empty() {
                return Err("'grep' must not be empty when provided".into());
            }
            let body = rustynet_mcp::read_file_capped(&canon, 8_000_000)?;
            let matched: Vec<&str> = body
                .lines()
                .filter(|l| l.contains(pattern))
                .take(tail)
                .collect();
            if matched.is_empty() {
                return Ok(format!(
                    "# job log {job_id} — grep \"{pattern}\"\n\n(no matching lines)\n"
                ));
            }
            return Ok(format!(
                "# job log {job_id} — grep \"{pattern}\" ({} match line(s))\n\n```\n{}\n```\n",
                matched.len(),
                matched.join("\n")
            ));
        }
        let body = rustynet_mcp::tail_file(&canon, tail)?;
        Ok(format!(
            "# job log {job_id} (last {tail} lines)\n\n```\n{}\n```\n",
            body.trim()
        ))
    }

    /// Locate ONE stage's log inside a confined run report dir and return its
    /// tail. Mirrors lab_state's get_stage_log: read `state/stages.tsv`
    /// (col0=name, col4=log path) for a row whose name matches `stage`
    /// (OS-prefix-stripped), resolving the log path report-relative / absolute /
    /// `./`-prefixed; if the TSV yields nothing, fall back to a `.log`/`.txt`
    /// filename containing the stage name. Read-only.
    fn tool_lab_stage_log(&self, args: &Value) -> Result<String, String> {
        let report_dir = arg_str(args, "report_dir").ok_or("missing 'report_dir'")?;
        let stage = arg_str(args, "stage").ok_or("missing 'stage'")?.trim();
        // Stage charset: ASCII alphanumeric, '-', '_' only — rejects traversal
        // ('.', '/'), whitespace, shell metachars. The stage only ever drives an
        // in-process substring match, but validate hard anyway.
        if stage.is_empty()
            || stage.len() > 128
            || !stage
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(format!(
                "invalid stage '{stage}': only ASCII letters, digits, '-' and '_' allowed"
            ));
        }
        let tail = args
            .get("tail")
            .and_then(|v| v.as_u64())
            .map(|n| n.clamp(1, 4000) as usize)
            .unwrap_or(400);
        let canon = self.confine(report_dir)?;
        if !canon.is_dir() {
            return Err(format!("'{report_dir}' is not a directory"));
        }
        // Strip OS prefixes so 'linux_stage_anchor' matches an 'anchor' row.
        let lower = stage.to_lowercase();
        let norm = lower
            .strip_prefix("linux_stage_")
            .or_else(|| lower.strip_prefix("macos_stage_"))
            .or_else(|| lower.strip_prefix("windows_stage_"))
            .unwrap_or(lower.as_str());

        let mut out = format!("# Stage log '{stage}' — {report_dir}\n\n");
        let mut matched_logs: Vec<PathBuf> = Vec::new();
        if let Ok(body) = std::fs::read_to_string(canon.join("state/stages.tsv")) {
            for line in body.lines().filter(|l| !l.trim().is_empty()) {
                let cols: Vec<&str> = line.split('\t').collect();
                if cols.len() < 6 {
                    continue;
                }
                let name_l = cols[0].to_lowercase();
                if !name_l.contains(norm) && !norm.contains(name_l.as_str()) {
                    continue;
                }
                out.push_str(&format!("- {} → {} (rc {})\n", cols[0], cols[2], cols[3]));
                // Resolve the log path (col 4): absolute, report-relative, or ./-prefixed.
                let raw = cols[4];
                for cand in [
                    PathBuf::from(raw),
                    canon.join(raw),
                    canon.join(raw.trim_start_matches("./")),
                ] {
                    if cand.is_file() && !matched_logs.iter().any(|m| m == &cand) {
                        matched_logs.push(cand);
                        break;
                    }
                }
            }
        }
        // If the TSV gave no log, fall back to filename matching.
        if matched_logs.is_empty() {
            let mut files: Vec<(String, u64)> = Vec::new();
            collect_repo_files(&canon, &canon, &mut files, 0);
            for (rel, _) in &files {
                let rel_l = rel.to_lowercase();
                if rel_l.contains(norm) && (rel_l.ends_with(".log") || rel_l.ends_with(".txt")) {
                    matched_logs.push(canon.join(rel));
                }
            }
        }
        // Re-confine every candidate before reading: a stages.tsv col-4 value
        // may be absolute or contain `..`, and a fallback filename may be a
        // symlink — canonicalize and require repo-root containment so the tail
        // can never read an out-of-tree file.
        let safe_logs: Vec<PathBuf> = matched_logs
            .iter()
            .filter_map(|c| self.confine_resolved(c))
            .collect();
        if safe_logs.is_empty() {
            out.push_str(
                "\nNo stage log located. Use lab_report_artifacts to browse, lab_report_grep to search, or lab_job_log for the run's combined log.\n",
            );
            return Ok(out);
        }
        for log in safe_logs.iter().take(2) {
            let rel = log.strip_prefix(&canon).unwrap_or(log);
            out.push_str(&format!("\n## {} (tail {tail})\n", rel.display()));
            match rustynet_mcp::tail_file(log, tail) {
                Ok(content) => out.push_str(&format!("```\n{}\n```\n", content.trim())),
                Err(e) => out.push_str(&format!("_cannot read: {e}_\n")),
            }
        }
        Ok(out)
    }

    /// Grep a pattern across a confined run report dir's files. argv-only:
    /// `rg -e <pattern> --` (or `grep -rn -e <pattern> --`) with cwd = the
    /// confined report_dir, so the search never escapes it and the pattern is
    /// NEVER interpolated into a shell string. Mirrors lab_state's grep_report
    /// scope. Read-only; bounded match count + truncate.
    fn tool_lab_report_grep(&self, args: &Value) -> Result<String, String> {
        let report_dir = arg_str(args, "report_dir").ok_or("missing 'report_dir'")?;
        let pattern = arg_str(args, "pattern").ok_or("missing 'pattern'")?;
        if pattern.is_empty() {
            return Err("'pattern' must not be empty".into());
        }
        if pattern.contains('\0') {
            return Err("pattern contains a NUL byte".into());
        }
        let max = args
            .get("max")
            .and_then(|v| v.as_u64())
            .map(|n| n.clamp(1, 500) as usize)
            .unwrap_or(80);
        let canon = self.confine(report_dir)?;
        if !canon.is_dir() {
            return Err(format!("'{report_dir}' is not a directory"));
        }
        // Search with cwd = the confined report dir; '.' as the path keeps the
        // search inside it and yields report-relative match paths.
        let (program, argv): (&str, Vec<&str>) = if which("rg") {
            (
                "rg",
                vec![
                    "--no-config",
                    "--no-heading",
                    "--line-number",
                    "--color=never",
                    "--max-count",
                    "200",
                    "-e",
                    pattern,
                    "--",
                    ".",
                ],
            )
        } else {
            (
                "grep",
                vec!["-rn", "--color=never", "-e", pattern, "--", "."],
            )
        };
        let outcome = run_with_timeout(
            program,
            &argv,
            &canon,
            &[],
            Duration::from_secs(SUBPROC_TIMEOUT_SECS),
        )?;
        let lines: Vec<&str> = outcome.stdout.lines().take(max).collect();
        if lines.is_empty() {
            // grep/rg exit 1 on "no matches" — that is not an error here.
            if !outcome.success && outcome.code != Some(1) {
                return Err(format!(
                    "{program} failed (exit {:?}): {}",
                    outcome.code,
                    outcome.stderr.trim()
                ));
            }
            return Ok(format!(
                "# report grep \"{pattern}\" — {report_dir}\n\n(no matches)\n"
            ));
        }
        Ok(format!(
            "# report grep \"{pattern}\" — {report_dir} ({} match line(s), via {program})\n\n{}\n",
            lines.len(),
            lines.join("\n")
        ))
    }

    /// List a confined run report dir's artifact files (repo-relative name +
    /// size), bounded. Mirrors lab_state's list_report_artifacts. Read-only.
    fn tool_lab_report_artifacts(&self, args: &Value) -> Result<String, String> {
        let report_dir = arg_str(args, "report_dir").ok_or("missing 'report_dir'")?;
        let canon = self.confine(report_dir)?;
        if !canon.is_dir() {
            return Err(format!("'{report_dir}' is not a directory"));
        }
        let mut files: Vec<(String, u64)> = Vec::new();
        collect_repo_files(&canon, &canon, &mut files, 0);
        files.sort();
        const CAP: usize = 400;
        let mut out = format!(
            "# Report artifacts — {report_dir} ({} file(s))\n\n",
            files.len()
        );
        for (rel, size) in files.iter().take(CAP) {
            out.push_str(&format!("- `{rel}` ({size} bytes)\n"));
        }
        if files.len() > CAP {
            out.push_str(&format!("\n... ({} more)\n", files.len() - CAP));
        }
        Ok(out)
    }

    /// Find a symbol's DEFINITION across the repo. The symbol is validated to
    /// Rust-identifier chars (ASCII alphanumeric + '_') BEFORE it is spliced into
    /// a FIXED regex template — so it cannot inject regex metacharacters. The
    /// search is argv-only (`rg -e <fixed-template> ...`, never a shell string)
    /// with cwd = repo_root; results are repo-relative. Read-only.
    fn tool_find_definition(&self, args: &Value) -> Result<String, String> {
        let symbol = arg_str(args, "symbol").ok_or("missing 'symbol'")?.trim();
        // Rust identifier charset ONLY: ASCII alphanumeric + '_'. Rejects regex
        // metacharacters ('.', '*', ';', '(', etc.), whitespace, everything else
        // — this is what makes the fixed-template splice injection-safe.
        if symbol.is_empty()
            || symbol.len() > 128
            || !symbol
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(format!(
                "invalid symbol '{symbol}': only ASCII letters, digits and '_' allowed (Rust identifier)"
            ));
        }
        let limit = args
            .get("limit")
            .and_then(|v| v.as_u64())
            .map(|n| n.clamp(1, 200) as usize)
            .unwrap_or(40);
        if !which("rg") {
            return Ok(format!(
                "# find_definition \"{symbol}\"\n\n(ripgrep `rg` not on PATH — install it, or use grep/find_files instead)\n"
            ));
        }
        // FIXED regex template; the validated symbol is the only interpolation
        // and contains no regex metacharacters. Matches Rust definition forms.
        let pattern = format!(
            r"(\bfn|\bstruct|\benum|\btrait|\bimpl|\btype|\bconst|\bstatic|\bmod)\s+{symbol}\b"
        );
        let outcome = run_with_timeout(
            "rg",
            &[
                "--no-config",
                "--no-heading",
                "--line-number",
                "--color=never",
                "-A2",
                "--max-count",
                "50",
                "-e",
                pattern.as_str(),
                "--",
                ".",
            ],
            &self.repo_root,
            &[],
            Duration::from_secs(SUBPROC_TIMEOUT_SECS),
        )?;
        let lines: Vec<&str> = outcome
            .stdout
            .lines()
            .take(limit)
            .map(strip_repo_prefix_in_line(&self.repo_root))
            .collect();
        if lines.is_empty() {
            // rg exits 1 on "no matches" — not an error here.
            if !outcome.success && outcome.code != Some(1) {
                return Err(format!(
                    "rg failed (exit {:?}): {}",
                    outcome.code,
                    outcome.stderr.trim()
                ));
            }
            return Ok(format!(
                "# find_definition \"{symbol}\"\n\n(no definition found)\n"
            ));
        }
        Ok(format!(
            "# find_definition \"{symbol}\" ({} line(s))\n\n{}\n",
            lines.len(),
            lines.join("\n")
        ))
    }

    /// Find REFERENCES (usages / call sites) of a Rust symbol across the repo —
    /// every `\bsymbol\b` occurrence, the definition included. Complements
    /// find_definition (which locates where a symbol is DECLARED): this shows where
    /// it is USED, so an agent can ground claims about impact and call sites.
    /// Read-only; the symbol is validated to the Rust-identifier charset so the
    /// fixed regex template is injection-safe.
    fn tool_find_references(&self, args: &Value) -> Result<String, String> {
        let symbol = arg_str(args, "symbol").ok_or("missing 'symbol'")?.trim();
        if symbol.is_empty()
            || symbol.len() > 128
            || !symbol
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(format!(
                "invalid symbol '{symbol}': only ASCII letters, digits and '_' allowed (Rust identifier)"
            ));
        }
        let limit = args
            .get("limit")
            .and_then(|v| v.as_u64())
            .map(|n| n.clamp(1, 300) as usize)
            .unwrap_or(80);
        if !which("rg") {
            return Ok(format!(
                "# find_references \"{symbol}\"\n\n(ripgrep `rg` not on PATH — grep for the name instead)\n"
            ));
        }
        // FIXED word-boundary template; the validated symbol is the only
        // interpolation and contains no regex metacharacters.
        let pattern = format!(r"\b{symbol}\b");
        let outcome = run_with_timeout(
            "rg",
            &[
                "--no-config",
                "--no-heading",
                "--line-number",
                "--color=never",
                "--max-count",
                "300",
                "-e",
                pattern.as_str(),
                "--",
                ".",
            ],
            &self.repo_root,
            &[],
            Duration::from_secs(SUBPROC_TIMEOUT_SECS),
        )?;
        let mapped: Vec<&str> = outcome
            .stdout
            .lines()
            .map(strip_repo_prefix_in_line(&self.repo_root))
            .collect();
        let total = mapped.len();
        if total == 0 {
            if !outcome.success && outcome.code != Some(1) {
                return Err(format!(
                    "rg failed (exit {:?}): {}",
                    outcome.code,
                    outcome.stderr.trim()
                ));
            }
            return Ok(format!(
                "# find_references \"{symbol}\"\n\n(no references found)\n"
            ));
        }
        let shown = &mapped[..total.min(limit)];
        let note = if total > shown.len() {
            format!(
                " — {total} total, showing {}; raise `limit` or narrow with grep",
                shown.len()
            )
        } else {
            String::new()
        };
        Ok(format!(
            "# find_references \"{symbol}\" ({} line(s){note})\n\n{}\n",
            shown.len(),
            shown.join("\n")
        ))
    }

    /// Run `cargo check` as a GROUNDING aid — confirm code compiles (and see the
    /// real compiler errors) for a crate, on the host (macOS+common) or the
    /// Windows cross-target (`target: "windows"` → x86_64-pc-windows-gnu). argv-only,
    /// validated scope, bounded; writes only to `target/`. Output is UNTRUSTED like
    /// any tool result — the authoritative pre-commit gate stays with the main agent.
    fn tool_cargo_check(&self, args: &Value) -> Result<String, String> {
        let crate_name = arg_str(args, "crate").and_then(validate_crate_name);
        let target = resolve_cargo_target(arg_str(args, "target"))?;
        let mut argv: Vec<&str> = vec!["check", "--quiet"];
        match crate_name {
            Some(c) => {
                argv.push("-p");
                argv.push(c);
            }
            None => argv.push("--workspace"),
        }
        if let Some(t) = target {
            argv.push("--target");
            argv.push(t);
        }
        let outcome = run_with_timeout(
            "cargo",
            &argv,
            &self.repo_root,
            &[],
            Duration::from_secs(CARGO_TOOL_TIMEOUT_SECS),
        )?;
        let scope = format!(
            "{}{}",
            crate_name
                .map(|c| format!("-p {c}"))
                .unwrap_or_else(|| "--workspace".into()),
            target.map(|t| format!(" --target {t}")).unwrap_or_default()
        );
        let diags = truncate_output(&outcome.stderr, 120, 12 * 1024);
        Ok(format!(
            "# cargo check {scope}\n\n{}\n\n{}",
            if outcome.success {
                "RESULT: OK — compiles."
            } else {
                "RESULT: FAILED — compile errors below (this is GROUND TRUTH for the diagnosis)."
            },
            if diags.trim().is_empty() {
                "(no diagnostics)".to_string()
            } else {
                format!("```\n{diags}\n```")
            }
        ))
    }

    /// Run a SCOPED `cargo test` as a grounding aid — confirm a specific test's
    /// current pass/fail (e.g. "does this test reproduce the bug?"). A `crate` is
    /// REQUIRED (full-workspace test is too heavy); an optional `test_filter`
    /// narrows it. argv-only, validated, bounded. UNTRUSTED output.
    fn tool_cargo_test(&self, args: &Value) -> Result<String, String> {
        let crate_name = arg_str(args, "crate").and_then(validate_crate_name).ok_or(
            "'crate' is required and must be a workspace crate name (alphanumeric/-/_); a full-workspace test run is too heavy",
        )?;
        let filter = arg_str(args, "test_filter")
            .map(str::trim)
            .filter(|s| !s.is_empty());
        if let Some(f) = filter
            && (f.len() > 128
                || !f
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b':'))
        {
            return Err(format!(
                "invalid test_filter '{f}': only letters, digits, '_' and ':' allowed"
            ));
        }
        let target = resolve_cargo_target(arg_str(args, "target"))?;
        let mut argv: Vec<&str> = vec!["test", "--quiet", "-p", crate_name];
        if let Some(t) = target {
            argv.push("--target");
            argv.push(t);
        }
        if let Some(f) = filter {
            argv.push(f);
        }
        let outcome = run_with_timeout(
            "cargo",
            &argv,
            &self.repo_root,
            &[],
            Duration::from_secs(CARGO_TOOL_TIMEOUT_SECS),
        )?;
        let scope = format!(
            "-p {crate_name}{}{}",
            target.map(|t| format!(" --target {t}")).unwrap_or_default(),
            filter.map(|f| format!(" '{f}'")).unwrap_or_default()
        );
        let out = truncate_output(&outcome.stdout, 80, 8 * 1024);
        let err = truncate_output(&outcome.stderr, 40, 4 * 1024);
        Ok(format!(
            "# cargo test {scope}\n\n{}\n\n```\n{out}\n{err}\n```",
            if outcome.success {
                "RESULT: tests PASSED."
            } else {
                "RESULT: tests FAILED / errored (ground truth)."
            }
        ))
    }
}

/// Repo-relative path to the UTM VM lab inventory (mirrors lab_state's
/// DEFAULT_INVENTORY). Read-only consumers confine this before reading.
const LAB_INVENTORY_PATH: &str = "documents/operations/active/vm_lab_inventory.json";

/// Repo-relative dir where background-job records + combined logs live (mirrors
/// lab_state's JOBS_SUBDIR). A job's log is `<JOBS_SUBDIR>/<job_id>.log`.
const JOBS_SUBDIR: &str = "state/mcp-jobs";

/// Recursively collect (repo-relative path, size) for every file under `dir`,
/// bounded by depth and count. Mirrors lab_state's `collect_files` so the report
/// tools enumerate a run dir's artifacts the same way.
fn collect_repo_files(dir: &Path, base: &Path, out: &mut Vec<(String, u64)>, depth: usize) {
    if depth > 8 || out.len() > 2000 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        // Do NOT follow symlinks. The walked dir is confined, but an artifact
        // inside it can be a symlink to an out-of-tree target; `file_type()`
        // (unlike `is_dir()`/`metadata()`) reports the link itself and does not
        // resolve it, so a symlinked dir or file is skipped rather than walked
        // or sized through. Mirrors tool_list_dir's symlink_metadata handling.
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            collect_repo_files(&p, base, out, depth + 1);
        } else if let Ok(rel) = p.strip_prefix(base) {
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            out.push((rel.to_string_lossy().to_string(), size));
        }
    }
}

/// Minimal quote-aware CSV line splitter (handles "quoted, fields" and ""
/// escapes) so the run-matrix summary reads the right columns even when later
/// columns (notes, specs) contain commas.
fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
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
        } else if c == '"' {
            in_quotes = true;
        } else if c == ',' {
            fields.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    fields.push(cur);
    fields
}

fn load_api_key() -> Result<String, String> {
    if let Ok(key) = std::env::var("DEEPSEEK_API_KEY") {
        let key = key.trim().to_string();
        if !key.is_empty() {
            return Ok(key);
        }
    }
    let home = std::env::var("HOME").unwrap_or_default();
    if !home.is_empty() {
        for rel in &["Desktop/deepseek_api.md", ".deepseek_api_key"] {
            let p = PathBuf::from(&home).join(rel);
            if p.exists() {
                let key = std::fs::read_to_string(&p)
                    .map_err(|e| format!("cannot read {}: {e}", p.display()))?
                    .trim()
                    .to_string();
                if !key.is_empty() {
                    return Ok(key);
                }
            }
        }
    }
    Err("No DeepSeek API key found (checked DEEPSEEK_API_KEY, ~/Desktop/deepseek_api.md, ~/.deepseek_api_key)".into())
}

/// Strip DeepSeek-native tool-call markup (`<｜｜DSML｜｜…>`) that leaks into the
/// content field when the model tries to invoke tools but none are advertised
/// (the budget-exhausted final answer disables tools, so a model that still wants
/// a tool emits it as text). Everything from the first such marker on is non-prose
/// tool markup, so we keep only the trimmed prose before it.
fn strip_dsml_markup(s: &str) -> String {
    const MARKER: &str = "\u{ff5c}\u{ff5c}DSML";
    match s.find(MARKER) {
        Some(i) => s[..i].trim_end_matches('<').trim().to_string(),
        None => s.trim().to_string(),
    }
}

/// Assemble the three triage-pipeline step outputs into the final multi-section
/// report. Pure (no I/O) so the report shape is unit-testable offline.
fn assemble_triage_report(research: &str, verified: &str, final_review: &str) -> String {
    format!(
        "# Live-lab failure triage\n\
         _Rigid pipeline: Flash research -> Flash verify -> v4-pro review (max reasoning). \
         All steps read-only + grounded; no code changes. UNTRUSTED — the main agent verifies \
         every claim before acting._\n\n\
         ## 1. Research — deepseek-v4-flash\n\n{research}\n\n\
         ## 2. Verification — deepseek-v4-flash\n\n{verified}\n\n\
         ## 3. Final review — deepseek-v4-pro (max reasoning)\n\n{final_review}\n"
    )
}

fn home_path(rel: &str) -> String {
    let home = std::env::var("HOME").unwrap_or_default();
    format!("{home}/{rel}")
}

/// Current wall-clock time as unix seconds (0 on a clock-before-epoch error).
/// Used to stamp persisted job records (started/finished).
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn overlay_loop_options(target_args: &mut Value, user_args: &Value) {
    let Some(obj) = target_args.as_object_mut() else {
        return;
    };
    for key in [
        "dry_run",
        "allow_concurrent",
        "max_steps",
        "triage_on_failure",
    ] {
        if let Some(v) = user_args.get(key) {
            obj.insert(key.to_string(), v.clone());
        }
    }
}

fn key_for_stage_or_cell(name: &str) -> Option<&'static str> {
    let n = name.to_ascii_lowercase();
    if n.contains("macos") {
        if n.contains("blind_exit") || n.contains("blind-exit") {
            return Some("macos_blind_exit");
        }
        if n.contains("admin") {
            return Some("macos_admin");
        }
        if n.contains("anchor") {
            return Some("macos_anchor");
        }
        if n.contains("relay") {
            return Some("macos_relay");
        }
        if n.contains("exit") || n.contains("nat") || n.contains("killswitch") {
            return Some("macos_exit");
        }
    }
    if n.contains("windows") {
        if n.contains("admin") {
            return Some("windows_admin");
        }
        if n.contains("anchor") {
            return Some("windows_anchor");
        }
        if n.contains("relay") {
            return Some("windows_relay");
        }
        if n.contains("exit") || n.contains("nat") || n.contains("killswitch") {
            return Some("windows_exit");
        }
    }
    None
}

fn extract_labrun_job_id(s: &str) -> Option<String> {
    let start = s.find("labrun-")?;
    let tail = &s[start..];
    let id: String = tail
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    if id.starts_with("labrun-") && id.len() > "labrun-".len() {
        Some(id)
    } else {
        None
    }
}

/// TERM-then-KILL the child's whole process group (the orchestrator spawns bash
/// workers + utmctl pushes; killing only the leader orphans them). Only invoked
/// on a genuine wall-clock timeout — a normal exit never reaches here.
/// `spawn_logged` makes the child a process-group leader, so `-pid` targets the
/// tree. Mirrors the lib's private `kill_child_tree`.
#[cfg(unix)]
fn kill_child_group(child: &mut std::process::Child) {
    let group = format!("-{}", child.id());
    let _ = std::process::Command::new("kill")
        .args(["-TERM", "--", &group])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    std::thread::sleep(Duration::from_millis(50));
    let _ = std::process::Command::new("kill")
        .args(["-KILL", "--", &group])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    let _ = child.kill();
}

#[cfg(unix)]
fn terminate_process_group(pgid: i32) {
    if pgid <= 1 || pgid == std::process::id() as i32 {
        return;
    }
    let group = format!("-{pgid}");
    let _ = std::process::Command::new("kill")
        .args(["-TERM", "--", &group])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    std::thread::sleep(Duration::from_millis(50));
    let _ = std::process::Command::new("kill")
        .args(["-KILL", "--", &group])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

#[cfg(not(unix))]
fn terminate_process_group(_pgid: i32) {}

#[cfg(not(unix))]
fn kill_child_group(child: &mut std::process::Child) {
    let _ = child.kill();
}

/// Whether a process with `pid` is currently alive. Used to decide whether a
/// `state=running` job record whose orchestrator was recorded at spawn is
/// genuinely in flight or a stale record left by a crashed/killed orchestrator.
///
/// On unix this is `kill -0`: a return of 0 means the process exists; a failure
/// is decoded by errno — EPERM (the process exists but is owned by another user,
/// so the signal was refused) ALSO means alive, while ESRCH means no such
/// process (dead). We don't link `libc` directly here (it's only a transitive
/// dep), so we shell out to `kill -0` — the same `kill`-subprocess pattern this
/// file already uses for `kill_child_group` — and read its exit status:
///   - exit 0 → alive
///   - exit != 0 → the shell `kill` could not signal it. macOS/Linux `kill`
///     return non-zero both for ESRCH (dead) and EPERM (alive-but-not-ours). To
///     keep the EPERM=alive semantic without parsing errno, we treat a non-zero
///     status conservatively as "could not prove dead" ONLY when the process is
///     genuinely ours; in practice the orchestrator is spawned by THIS user, so
///     EPERM does not arise and a non-zero status reliably means dead. We still
///     fail toward "alive" (return true) if the `kill` binary itself can't run,
///     so a probe failure never wrongly frees the singleton slot.
///
/// pid 0 / the current pid are special-cased (0 is never a real single process
/// target for our purposes; the current pid is trivially alive).
#[cfg(unix)]
fn pid_is_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    if pid == std::process::id() {
        return true;
    }
    match std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
    {
        // `kill -0` succeeded → the process exists and we may signal it.
        Ok(s) if s.success() => true,
        // `kill -0` ran but returned non-zero → ESRCH (dead) for a process we
        // own; treat as dead. (EPERM for another user's process does not arise
        // for our own-spawned orchestrator.)
        Ok(_) => false,
        // The `kill` binary could not be launched at all → we cannot prove the
        // process is dead, so fail toward "alive" and keep the slot held rather
        // than wrongly freeing it on a probe failure.
        Err(_) => true,
    }
}

/// Non-unix fallback: without a portable cheap liveness probe, assume alive so a
/// recorded pid never wrongly frees the singleton slot. (The deepseek live-lab
/// orchestrator runs on the unix lab host; this branch exists only so the binary
/// compiles on other targets.)
#[cfg(not(unix))]
fn pid_is_alive(_pid: u32) -> bool {
    true
}

/// Build the `ops vm-lab-orchestrate-live-lab` argument vector (everything after
/// `cargo run --quiet -p rustynet-cli -- ops`) for a deepseek_lab_run. Pure +
/// deterministic so it is unit-testable: there is NO LLM in this deploy path —
/// the worker shells out to the same hardened orchestrator the lab-state MCP
/// drives. Safe defaults: trust the prepared inventory, skip the slow gates/soak/
/// cross-network legs, and ship the working tree (so uncommitted patches deploy).
#[allow(clippy::too_many_arguments)] // a flat, deterministic CLI-arg builder; each arg is distinct.
fn build_orchestrator_args(
    inventory: &str,
    ssh_identity: &str,
    known_hosts: &str,
    report_dir: &str,
    macos_vm: Option<&str>,
    windows_vm: Option<&str>,
    exit_vm: Option<&str>,
    client_vm: Option<&str>,
    rebuild_nodes: Option<&str>,
    exit_platform: Option<&str>,
    relay_platform: Option<&str>,
    anchor_platform: Option<&str>,
    admin_platform: Option<&str>,
    blind_exit_platform: Option<&str>,
    entry_vm: Option<&str>,
    macos_promote_exit: bool,
    legacy_bash: bool,
    dry_run: bool,
    windows_only: bool,
    skip_linux_live_suite: bool,
) -> Vec<String> {
    let mut a: Vec<String> = vec!["vm-lab-orchestrate-live-lab".to_string()];
    a.extend(["--inventory".to_string(), inventory.to_string()]);
    a.extend(["--ssh-identity-file".to_string(), ssh_identity.to_string()]);
    a.extend(["--known-hosts-file".to_string(), known_hosts.to_string()]);
    a.extend(["--report-dir".to_string(), report_dir.to_string()]);
    a.push("--trust-inventory-ready".to_string());
    a.push("--skip-gates".to_string());
    a.push("--skip-soak".to_string());
    a.push("--skip-cross-network".to_string());
    a.extend(["--source-mode".to_string(), "working-tree".to_string()]);
    if let Some(m) = macos_vm {
        a.extend(["--macos-vm".to_string(), m.to_string()]);
    }
    if let Some(w) = windows_vm {
        a.extend(["--windows-vm".to_string(), w.to_string()]);
    }
    if let Some(e) = exit_vm {
        a.extend(["--exit-vm".to_string(), e.to_string()]);
    }
    if let Some(c) = client_vm {
        a.extend(["--client-vm".to_string(), c.to_string()]);
    }
    if let Some(r) = rebuild_nodes {
        a.extend(["--rebuild-nodes".to_string(), r.to_string()]);
    }
    // Role-platform selectors: elect a mac/win node into the role so the focused
    // role cell runs live instead of skipping (validated upstream to linux|macos|
    // windows). Bare --macos-promote-exit is the Option-B macOS secondary-exit
    // selector (is_macos_active_exit = config.macos_promote_exit).
    if let Some(p) = exit_platform {
        a.extend(["--exit-platform".to_string(), p.to_string()]);
    }
    if let Some(p) = relay_platform {
        a.extend(["--relay-platform".to_string(), p.to_string()]);
    }
    if let Some(p) = anchor_platform {
        a.extend(["--anchor-platform".to_string(), p.to_string()]);
    }
    if let Some(p) = admin_platform {
        a.extend(["--admin-platform".to_string(), p.to_string()]);
    }
    if let Some(p) = blind_exit_platform {
        a.extend(["--blind-exit-platform".to_string(), p.to_string()]);
    }
    if let Some(e) = entry_vm {
        a.extend(["--entry-vm".to_string(), e.to_string()]);
    }
    if macos_promote_exit {
        a.push("--macos-promote-exit".to_string());
    }
    // The proven orchestrator path for the mac/win ROLE stages
    // (activate_macos_exit_role + capture, the relay/anchor lifecycle). The
    // default Rust path may not drive every role stage; the legacy bash
    // orchestrator does (it flipped relay + reached every prior macOS role
    // stage). Mutually exclusive with --node (deepseek_lab_run never uses --node).
    if legacy_bash {
        a.push("--legacy-bash-orchestrator".to_string());
    }
    if windows_only {
        a.push("--windows-only".to_string());
    }
    // Skip the Linux LIVE-VALIDATION SUITE (anchor/role-switch/exit-handoff/
    // relay/two-hop/managed-dns/chaos — the ~30-45 min time sink) while still
    // running setup (bootstrap + membership + signed-bundle distribution) and
    // the mac/win role stages. Use with a role-platform selector to iterate a
    // single mac/win cell fast; the mac/win stages gate on setup's distribute_*
    // outcomes, not on the Linux live suite, so they stay fully exercised.
    if skip_linux_live_suite {
        a.push("--skip-linux-live-suite".to_string());
    }
    if dry_run {
        a.push("--dry-run".to_string());
    }
    a
}

fn recovery_orchestrator_args(
    inventory: &str,
    ssh_identity: &str,
    known_hosts: &str,
    report_dir: &str,
    dry_run: bool,
) -> Vec<String> {
    let mut a: Vec<String> = vec!["vm-lab-orchestrate-live-lab".to_string()];
    a.extend(["--inventory".to_string(), inventory.to_string()]);
    a.extend(["--ssh-identity-file".to_string(), ssh_identity.to_string()]);
    a.extend(["--known-hosts-file".to_string(), known_hosts.to_string()]);
    a.extend(["--report-dir".to_string(), report_dir.to_string()]);
    a.push("--stop-after-ready".to_string());
    a.extend(["--source-mode".to_string(), "working-tree".to_string()]);
    if dry_run {
        a.push("--dry-run".to_string());
    }
    a
}

/// Resolved connection details for a lab guest, parsed from the inventory.
struct GuestConn {
    platform: String,
    utm_name: Option<String>,
    ssh_target: Option<String>,
    ssh_user: Option<String>,
    ssh_password: Option<String>,
}

/// Fixed read-only diagnostic command (argv) for a Linux guest, run via
/// `utmctl exec` (out-of-band — works even when the guest's SSH is wedged).
fn linux_guest_cmd(check: &str) -> Option<&'static [&'static str]> {
    Some(match check {
        "network" => &["/usr/sbin/ip", "-br", "addr"],
        "routes" => &["/usr/sbin/ip", "route"],
        "dns" => &["/bin/cat", "/etc/resolv.conf"],
        "service" | "daemon" => &["/usr/bin/systemctl", "is-active", "rustynetd"],
        "ports" => &["/usr/bin/ss", "-tlnp"],
        "firewall" => &["/usr/sbin/nft", "list", "ruleset"],
        _ => return None,
    })
}

/// Fixed read-only diagnostic command (one remote-shell string) for a macOS or
/// Windows guest, run over SSH. NOT caller-controlled — a closed enum, so even
/// though SSH invokes the remote shell there is nothing to inject.
fn ssh_guest_cmd(platform: &str, check: &str) -> Option<&'static str> {
    Some(match (platform, check) {
        ("macos", "network") => "ifconfig -a",
        ("macos", "routes") => "netstat -rn",
        ("macos", "dns") => "scutil --dns",
        ("macos", "service" | "daemon") => {
            "launchctl list | grep -i rustynet || echo '(no rustynet launchd job listed)'"
        }
        ("macos", "ports") => "lsof -nP -iTCP -sTCP:LISTEN",
        ("macos", "firewall") => {
            "sudo -n pfctl -sr 2>&1 || echo '(pf rules need sudo; add a NOPASSWD sudoers line for /sbin/pfctl to inspect them)'"
        }
        ("windows", "network") => "powershell -NoProfile -Command \"ipconfig /all\"",
        ("windows", "routes") => "powershell -NoProfile -Command \"route print\"",
        ("windows", "dns") => {
            "powershell -NoProfile -Command \"Get-DnsClientServerAddress | Format-Table -AutoSize | Out-String -Width 200\""
        }
        ("windows", "service" | "daemon") => {
            "powershell -NoProfile -Command \"Get-Service rustynet* | Format-Table -AutoSize | Out-String\""
        }
        ("windows", "ports") => {
            "powershell -NoProfile -Command \"netstat -ano | Select-String LISTENING\""
        }
        ("windows", "firewall") => {
            "powershell -NoProfile -Command \"Get-NetFirewallRule -DisplayName 'rustynet*' -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String\""
        }
        _ => return None,
    })
}

/// Format a guest-diagnostic command outcome into a report block.
fn format_guest_output(
    vm_alias: &str,
    check: &str,
    platform: &str,
    cmd: &str,
    stdout: &str,
    stderr: &str,
) -> String {
    let mut out = format!("# lab_guest_exec {vm_alias} [{check}] ({platform})\n\n`{cmd}`\n\n");
    let stdout = stdout.trim();
    if !stdout.is_empty() {
        out.push_str(&format!(
            "```\n{}\n```\n",
            truncate_output(stdout, 200, 12 * 1024)
        ));
    }
    let stderr = stderr.trim();
    if !stderr.is_empty() {
        out.push_str(&format!(
            "\n_stderr:_ {}\n",
            truncate_output(stderr, 20, 2000)
        ));
    }
    if stdout.is_empty() && stderr.is_empty() {
        out.push_str("(no output)\n");
    }
    out
}

/// Validate a workspace crate name for the cargo grounding tools: ASCII
/// alphanumeric + '-'/'_' only (no path, no flags, no shell metacharacters).
fn validate_crate_name(s: &str) -> Option<&str> {
    let t = s.trim();
    (!t.is_empty()
        && t.len() <= 64
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
    .then_some(t)
}

/// Resolve a cargo `--target` from a friendly OS name. Only the host (default)
/// and the Windows cross-target are allowed — never an arbitrary triple.
fn resolve_cargo_target(s: Option<&str>) -> Result<Option<&'static str>, String> {
    match s.map(str::trim) {
        None | Some("") | Some("host") | Some("macos") | Some("mac") => Ok(None),
        Some("windows") | Some("win") => Ok(Some("x86_64-pc-windows-gnu")),
        Some(other) => Err(format!(
            "unsupported target '{other}': use 'host'/'macos' (this machine) or 'windows' (x86_64-pc-windows-gnu cross-check)"
        )),
    }
}

fn resolve_model(model_str: &str) -> &'static str {
    match model_str.to_lowercase().as_str() {
        "pro" | "reasoner" | "deepseek-reasoner" | "deepseek-v4-pro" => PRO_MODEL,
        _ => FLASH_MODEL,
    }
}

fn build_user_prompt(intent_label: &str, prompt: &str, context: Option<&str>) -> String {
    match context {
        Some(ctx) if !ctx.trim().is_empty() => {
            format!("[{intent_label}]\n\n## Context\n\n{ctx}\n\n## Task\n\n{prompt}")
        }
        _ => format!("[{intent_label}]\n\n{prompt}"),
    }
}

fn get_str<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key)?.as_str()
}

fn arg_str<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key)?.as_str()
}

fn utmctl_path() -> String {
    std::env::var("RUSTYNET_UTMCTL_PATH")
        .unwrap_or_else(|_| "/Applications/UTM.app/Contents/MacOS/utmctl".to_string())
}

/// True if `program` resolves on PATH (used to prefer ripgrep over grep).
fn which(program: &str) -> bool {
    let Ok(path) = std::env::var("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| {
        let candidate = dir.join(program);
        candidate.is_file()
    })
}

/// Host validation for `lab_node_reachable`: IPv4/IPv6 literal OR a simple
/// hostname. Rejects anything containing shell metacharacters (defensive — the
/// host only ever reaches a socket API, never a Command arg, but validate
/// strictly anyway).
fn is_valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 255 {
        return false;
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    // Hostname: labels of [A-Za-z0-9-], separated by '.', no leading/trailing '-'.
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

/// Compact, single-line render of a tool's args for the audit trace.
fn summarize_args(args: &Value) -> String {
    let s = serde_json::to_string(args).unwrap_or_default();
    truncate_output(&s, 1, 120).replace('\n', " ")
}

/// Returns a closure that strips an absolute repo-root prefix from a grep/rg
/// output line, so the model sees repo-relative `path:line` citations.
fn strip_repo_prefix_in_line(repo_root: &Path) -> impl Fn(&str) -> &str + '_ {
    move |line: &str| {
        let prefix = format!("{}/", repo_root.display());
        line.strip_prefix(&prefix).unwrap_or(line)
    }
}

const AGENT_SYSTEM_PROMPT: &str = "\
You are a Rustynet research assistant with READ-ONLY tools to inspect the LOCAL \
repository and UTM lab on this machine. Rustynet is a security-first, Rust-first \
mesh-VPN codebase. \
\
You CANNOT edit, write, create, delete, or move anything — your tools only read. \
Never claim that you changed, fixed, or wrote any file; you are not able to. \
\
ALWAYS gather ground truth with the tools before asserting ANY fact about the code, \
the lab, or the VMs. Do NOT answer from assumption or training-data recall about this \
specific repo. If the question is about current state — a file's contents, whether the \
code does X, a VM's power state, the latest live-lab run result, what was already tried \
— you MUST call a tool first; only synthesize after you have evidence. Cite it \
concretely: `path:line` for code, the exact command/output otherwise. \
\
Tools available to you on EVERY turn: \
- read_file / list_dir / grep — inspect any file under the repo root. \
- find_files — locate repo files by path glob/substring (e.g. '*.toml', 'exit_nat'). \
- git (read-only subcommands) — history, diffs, blame, show a blob at a ref. \
- utm_vm_status — UTM VM power state (started/stopped) for every lab VM. \
- lab_inventory — the lab roster: alias, platform, OS, lab_role, ssh_user, mesh_ip, IPs \
  (credentials omitted). USE THIS to learn which nodes/roles/OSes exist. \
- lab_node_reachable — TCP-probe a lab host (is its :22 / daemon port up?). \
- lab_guest_exec — run ONE fixed read-only diagnostic inside a running guest of ANY \
  OS (Linux via utmctl exec; macOS/Windows over SSH), for LIVE state. \
  check=network|routes|dns|service|ports|firewall, mapped per-OS (e.g. firewall = nft \
  ruleset on Linux, pf rules on macOS, Get-NetFirewallRule on Windows). The command is \
  fixed, not caller-controlled; it cannot write or run arbitrary commands. USE THIS for \
  live cross-OS network/DNS/service/ports/firewall state. \
- lab_run_status — recent live-lab run results from the run matrix: commit, overall \
  pass/fail, first-failed stage, and per-stage status (e.g. two_hop, relay). USE THIS \
  for 'what's the latest lab status / did stage X pass'. \
- lab_run_detail — drill into ONE run report dir: per-stage status, validator pass/fail, \
  and overall_result / first_failed_stage. USE THIS to dissect a specific run. \
- lab_jobs — recent live-lab background jobs (job_id, state, overall_result, mode, \
  report_dir). USE THIS to get a job_id (→ lab_job_log) and a report_dir (→ the lab_* \
  report drill-in tools below). \
- lab_loop_journal — the durable findings journal the lab loop writes (hypotheses, \
  root causes, fixes, blockers). USE THIS for 'what has already been tried / found'. \
- lab_job_log — tail of (or grep within) a job's combined log at \
  state/mcp-jobs/<job_id>.log, where the orchestrator/setup-stage errors live \
  (bootstrap_hosts, cleanup_hosts, the offline cargo build error, SSH errors). \
  Read-only; pass a job_id from lab_jobs. \
- lab_stage_log — tail of ONE stage's log inside a run report_dir (from \
  state/stages.tsv, else a matching .log/.txt). Read-only; pass report_dir + stage. \
- lab_report_grep — grep a pattern across a run report_dir's files; returns \
  report-relative path:line. Read-only; pass report_dir + pattern. \
- lab_report_artifacts — list a run report_dir's files (name + size). Read-only; pass \
  report_dir, then read/grep specific files. \
- find_definition — find a symbol's DEFINITION (fn/struct/enum/trait/impl/type/const/ \
  static/mod <symbol>) across the repo with context. Read-only; the symbol must be a \
  Rust identifier. \
- host_system_info — this host's OS/arch. \
- host_disk_status — host disk usage (df -h) for the repo volume and '/'. \
For per-run drill-in, get a report_dir from lab_jobs / lab_run_status, then use \
lab_report_artifacts → lab_stage_log / lab_report_grep (and lab_job_log for the combined \
log). Outputs are size-bounded; if truncated, narrow the range or grep. \
\
Work within the step budget: plan, inspect with tools, then give a precise \
evidence-backed answer. When you have enough, stop calling tools and answer.";

/// System prompt for the `deepseek_doc_sync` tool: a PROPOSE-ONLY, READ-ONLY
/// docs-sync role. It reuses the same grounded loop as the agent but with the
/// repo-reads-only tool set (no lab/guest/cargo tools) and must emit a structured
/// list of exact docs-only edits a human can apply by string replacement.
const DOC_SYNC_SYSTEM_PROMPT: &str = "\
You are the Rustynet DOCUMENTATION-SYNC assistant. After a lab-verified fix/patch lands, \
your job is to PROPOSE the exact documentation edits that keep the repo's docs in sync \
with that change. Rustynet is a security-first, Rust-first mesh-VPN codebase. \
\
You are PROPOSE-ONLY and READ-ONLY. You have ONLY repo-reads-only tools (read_file, \
list_dir, grep, find_files, find_definition, find_references, and read-only git). You \
have NO write/edit tool and NO lab/guest tool — you CANNOT change any file and you write \
NOTHING to disk. A human applies your proposed edits. Never claim you changed, fixed, or \
wrote anything. \
\
FOLLOW THESE RULES EXACTLY: \
\
1) READ THE CURRENT DOCS FIRST, before proposing anything. At minimum survey: the active \
   ledgers under documents/operations/active/ (especially \
   CrossPlatformRoleParityPlan_2026-06-21.md and \
   CrossPlatformRoleParityRoadmap_2026-06-22.md), documents/CODE_MAP.md, the root \
   README.md, AGENTS.md, CLAUDE.md, the index files documents/README.md, \
   documents/operations/README.md, documents/operations/active/README.md, and the \
   run-matrix doc documents/operations/LiveLabRunMatrix.md. Read with read_file/grep so \
   your old_strings are copied verbatim from the CURRENT text. Use doc_hints to prioritize \
   which docs to open first, but still survey the indexes for ripple effects. \
\
2) PROPOSE A STRUCTURED LIST OF EXACT EDITS. For EACH edit emit a clearly labeled block \
   with four fields: \
     - file: the repo-relative path (e.g. documents/operations/active/Foo.md). \
     - old_string: text copied VERBATIM from the current doc, character-for-character, \
       long/unique enough to locate deterministically (include enough surrounding context \
       that it appears exactly once in that file). \
     - new_string: the replacement text. \
     - rationale: one line on why this edit is needed. \
   The old_string MUST be copy-paste-applicable by a human or tool doing an EXACT string \
   replacement — if you are unsure the text is current, read the file again rather than \
   guess. Present each edit so a reader can apply it mechanically. \
\
3) DOCS ONLY. Only propose edits to files under documents/** or the root README.md / \
   AGENTS.md / CLAUDE.md. NEVER propose an edit to source code, scripts, configs, \
   Cargo.toml, or anything outside docs. If you believe code/tests/scripts also need to \
   change, SAY SO IN PROSE in a separate note — do NOT emit it as a structured edit. \
\
4) MIRROR RULE. AGENTS.md and CLAUDE.md are byte-for-byte mirrored. ANY proposed edit to \
   one MUST be accompanied by the IDENTICAL edit to the other (same old_string/new_string), \
   as a separate edit block for each file. \
\
5) INDEX-SYNC. If the change adds, removes, renames, or repurposes a doc, propose the \
   matching update to the relevant index file (documents/README.md, \
   documents/operations/README.md, documents/operations/active/README.md) so the docs map \
   does not drift. \
\
6) DO NOT INVENT evidence, status, dates, or commit SHAs. Reflect ONLY what the provided \
   change_summary + commit + evidence assert. If a doc currently claims something the new \
   evidence contradicts, propose the correction. If you CANNOT verify a claim against the \
   repo, FLAG it in prose rather than fabricating a value. Never upgrade a status cell or \
   invent a run id the inputs did not give you. \
\
7) YOU PROPOSE ONLY — you write nothing to disk; a human applies your edits. END YOUR \
   ANSWER WITH TWO SECTIONS: \
     (a) ## Proposed edits — the structured edit list from rule 2 (or 'No edits needed' \
         with the reason if the docs are already in sync). \
     (b) ## Considered, no change needed — name every doc you actually opened/checked that \
         needs no edit, so the human knows your coverage. \
   If rule 3 surfaced any non-doc change, add a short ## Out-of-scope note (prose) naming \
   it. \
\
Ground every old_string in text you actually read this run. Stay within the step budget: \
read the relevant docs, then write the structured proposal as plain prose (no tool-call \
syntax in the final answer).";

/// The OpenAI-style tool-definition array advertised to DeepSeek. All read-only.
fn agent_tool_definitions() -> Value {
    json!([
        fn_tool(
            "read_file",
            "Read a file from the local Rustynet repo. Path is repo-relative; \
             traversal and symlink escapes are rejected.",
            json!({
                "path": {"type": "string", "description": "Repo-relative file path, e.g. 'crates/rustynet-control/src/lib.rs'"},
                "max_bytes": {"type": "integer", "description": "Max bytes to read (default 65536, hard max 262144)"}
            }),
            &["path"],
        ),
        fn_tool(
            "list_dir",
            "List a directory in the local Rustynet repo. Returns each entry's name, \
             type (file/dir/symlink), and size in bytes.",
            json!({
                "path": {"type": "string", "description": "Repo-relative directory path, e.g. 'crates' or '.'"}
            }),
            &["path"],
        ),
        fn_tool(
            "grep",
            "Search the local Rustynet repo for a pattern (ripgrep if available, else grep -rn). \
             Returns repo-relative path:line matches.",
            json!({
                "pattern": {"type": "string", "description": "Regex/text pattern to search for"},
                "path": {"type": "string", "description": "Optional repo-relative subdirectory or file to confine the search (default: whole repo)"},
                "max_results": {"type": "integer", "description": "Max match lines to return (default 80, cap 500)"},
                "context": {"type": "integer", "description": "Optional surrounding context lines per match (-C N, 0-10), to see the code around a hit"}
            }),
            &["pattern"],
        ),
        fn_tool(
            "git",
            "Run a READ-ONLY git command in the repo. Only inspection subcommands are allowed \
             (log, show, diff, status, blame, rev-parse, ls-files, cat-file, describe, shortlog, \
             branch, tag, rev-list, ls-tree, grep, for-each-ref). Mutating commands are rejected.",
            json!({
                "args": {"type": "array", "items": {"type": "string"}, "description": "git argv, e.g. [\"log\",\"--oneline\",\"-5\"] or [\"show\",\"HEAD:Cargo.toml\"]"}
            }),
            &["args"],
        ),
        fn_tool(
            "utm_vm_status",
            "List the local UTM virtual machines and their power state (started/stopped). \
             Read-only; does not start, stop, or exec into any VM.",
            json!({}),
            &[],
        ),
        fn_tool(
            "lab_node_reachable",
            "Probe TCP reachability of a lab host (default port 22) via a connect timeout. \
             Read-only; opens then drops a socket, sends no payload.",
            json!({
                "host": {"type": "string", "description": "IP address or simple hostname"},
                "port": {"type": "integer", "description": "TCP port (default 22)"}
            }),
            &["host"],
        ),
        fn_tool(
            "host_system_info",
            "Return read-only facts about this host: OS, architecture, and `uname -a` output. \
             Useful for cross-platform Rustynet context.",
            json!({}),
            &[],
        ),
        fn_tool(
            "lab_run_status",
            "Summarize recent live-lab runs from the run matrix: per run the start time, git \
             commit, overall pass/fail, first-failed stage, and the linux two_hop / relay stage \
             status. Use to answer 'what is the latest live-lab result' or 'did stage X pass \
             recently'. Read-only.",
            json!({
                "limit": {"type": "integer", "description": "How many most-recent runs to show (default 10, max 50)"}
            }),
            &[],
        ),
        fn_tool(
            "lab_loop_journal",
            "Return the most recent notes from the lab loop's durable findings journal \
             (hypotheses, root causes, fixes, blockers the loop recorded). Use to answer 'what \
             has already been tried / found'. Read-only.",
            json!({
                "limit": {"type": "integer", "description": "How many most-recent notes to show (default 15, max 100)"}
            }),
            &[],
        ),
        fn_tool(
            "lab_inventory",
            "Summarize the UTM VM lab inventory: per node the alias, platform (linux/macos/windows), \
             OS string, lab_role, ssh_user, mesh_ip, and known IP(s). Read-only file read. \
             Credentials are intentionally omitted.",
            json!({}),
            &[],
        ),
        fn_tool(
            "lab_jobs",
            "List the most-recent live-lab background jobs from state/mcp-jobs/, newest first: per \
             job the job_id, completion state (passed/failed/ended), overall_result, and mode. \
             Read-only; if the jobs dir is absent it says so.",
            json!({
                "limit": {"type": "integer", "description": "How many most-recent jobs to show (default 10, max 50)"}
            }),
            &[],
        ),
        fn_tool(
            "lab_run_detail",
            "Summarize one live-lab run report directory: per-stage status from state/stages.tsv, \
             validator pass/fail from validator_results.json, and overall_result / first_failed_stage \
             from the run's matrix row. Read-only; the report_dir is confined to the repo.",
            json!({
                "report_dir": {"type": "string", "description": "Repo-relative run report directory, e.g. 'state/live-lab-<run-id>'"}
            }),
            &["report_dir"],
        ),
        fn_tool(
            "find_files",
            "Find repo files whose PATH matches a glob/substring (rg --files -g if available, else \
             git ls-files filtered by substring). Returns repo-relative paths. Read-only.",
            json!({
                "pattern": {"type": "string", "description": "Glob or path substring, e.g. '*.toml' or 'exit_nat'"},
                "limit": {"type": "integer", "description": "Max paths to return (default 100, cap 1000)"}
            }),
            &["pattern"],
        ),
        fn_tool(
            "host_disk_status",
            "Report read-only host disk usage (`df -h`) for the repo filesystem and `/`. \
             Useful for spotting a full disk before a lab run. Read-only.",
            json!({}),
            &[],
        ),
        fn_tool(
            "lab_guest_exec",
            "Run ONE fixed read-only diagnostic command inside a running lab guest of ANY OS, to \
             gather LIVE runtime state. Linux via utmctl exec (out-of-band); macOS + Windows over \
             SSH (creds from the inventory). The command is selected by `check`, NOT \
             caller-controlled — there is no arbitrary exec and no writes. checks: network \
             (ip/ifconfig/ipconfig), routes, dns (resolv.conf / scutil / Get-DnsClientServerAddress), \
             service (rustynetd / launchd / Windows service), ports (ss/lsof/netstat listeners), \
             firewall (nft ruleset / pf rules / Get-NetFirewallRule). Use this to ground a cross-OS \
             diagnosis in the guest's actual state. Fails closed if absent / not running / no creds.",
            json!({
                "vm_alias": {"type": "string", "description": "Inventory alias of any lab guest, e.g. 'debian-headless-1', 'macos-utm-1', 'windows-utm-1'"},
                "check": {"type": "string", "enum": ["network", "routes", "dns", "service", "ports", "firewall"], "description": "Which fixed read-only diagnostic to run (mapped per-OS)"}
            }),
            &["vm_alias", "check"],
        ),
        fn_tool(
            "lab_job_log",
            "Read the tail of (or, with `grep`, the matching lines from) a live-lab background \
             job's combined log at state/mcp-jobs/<job_id>.log — where the orchestrator / \
             setup-stage errors live (bootstrap_hosts, cleanup_hosts, the offline cargo build \
             error, SSH errors). Get the job_id from lab_jobs. Read-only; an absent log is \
             reported, not an error.",
            json!({
                "job_id": {"type": "string", "description": "Job id from lab_jobs, e.g. 'll-1718000000000-1234-0'"},
                "tail": {"type": "integer", "description": "Last N lines to return (default 200, max 2000)"},
                "grep": {"type": "string", "description": "Optional: return only lines containing this substring (matched in-process, not a shell/regex)"}
            }),
            &["job_id"],
        ),
        fn_tool(
            "lab_stage_log",
            "Locate ONE stage's log inside a run report dir (from state/stages.tsv, falling back \
             to a matching .log/.txt file) and return its tail. Get the report_dir from \
             lab_jobs / lab_run_status. Read-only; the report_dir is confined to the repo.",
            json!({
                "report_dir": {"type": "string", "description": "Repo-relative run report directory, e.g. 'state/live-lab-<run-id>'"},
                "stage": {"type": "string", "description": "Stage name (OS prefix optional), e.g. 'anchor' or 'linux_stage_two_hop'"},
                "tail": {"type": "integer", "description": "Last N log lines to return (default 400, max 4000)"}
            }),
            &["report_dir", "stage"],
        ),
        fn_tool(
            "lab_report_grep",
            "Grep a pattern across all files in a run report dir (ripgrep if available, else \
             grep -rn). Returns report-relative path:line matches. Get the report_dir from \
             lab_jobs / lab_run_status. Read-only; the report_dir is confined to the repo.",
            json!({
                "report_dir": {"type": "string", "description": "Repo-relative run report directory"},
                "pattern": {"type": "string", "description": "Regex/text pattern to search for in the run's files"},
                "max": {"type": "integer", "description": "Max match lines to return (default 80, cap 500)"}
            }),
            &["report_dir", "pattern"],
        ),
        fn_tool(
            "lab_report_artifacts",
            "List the artifact files in a run report dir (report-relative name + size in bytes). \
             Get the report_dir from lab_jobs / lab_run_status, then read or grep specific files \
             with read_file / lab_report_grep / lab_stage_log. Read-only; confined to the repo.",
            json!({
                "report_dir": {"type": "string", "description": "Repo-relative run report directory"}
            }),
            &["report_dir"],
        ),
        fn_tool(
            "find_definition",
            "Find a symbol's DEFINITION across the repo (fn/struct/enum/trait/impl/type/const/\
             static/mod <symbol>) via ripgrep with a couple lines of context. The symbol must be \
             a Rust identifier (letters/digits/underscore). Returns repo-relative path:line. \
             Read-only.",
            json!({
                "symbol": {"type": "string", "description": "Rust identifier to find the definition of, e.g. 'DeepSeekServer' or 'run_with_timeout'"},
                "limit": {"type": "integer", "description": "Max result lines to return (default 40, cap 200)"}
            }),
            &["symbol"],
        ),
        fn_tool(
            "find_references",
            "Find every USAGE / call site of a Rust symbol across the repo (\\bsymbol\\b, the \
             definition included) via ripgrep. Complements find_definition: that shows where a \
             symbol is DECLARED, this shows where it is USED — for impact + call-site grounding. \
             The symbol must be a Rust identifier. Returns repo-relative path:line. Read-only.",
            json!({
                "symbol": {"type": "string", "description": "Rust identifier to find usages of, e.g. 'run_triage' or 'MacosKillswitchSpec'"},
                "limit": {"type": "integer", "description": "Max result lines to return (default 80, cap 300)"}
            }),
            &["symbol"],
        ),
        fn_tool(
            "cargo_check",
            "GROUNDING aid: run `cargo check` to confirm code COMPILES (and see the real compiler \
             errors) — on the host (macOS + common code) or, with target='windows', the \
             x86_64-pc-windows-gnu cross-target (Windows cfg code). Scope to a crate for speed. \
             Confirms a compile claim by RUNNING it instead of inferring. Read-only w.r.t. the repo \
             (writes only target/); output is UNTRUSTED like any tool result.",
            json!({
                "crate": {"type": "string", "description": "Workspace crate to check (e.g. 'rustynetd'); omit to check the whole --workspace (slower)"},
                "target": {"type": "string", "description": "'host'/'macos' (default, this machine) or 'windows' (x86_64-pc-windows-gnu cross-check)"}
            }),
            &[],
        ),
        fn_tool(
            "cargo_test",
            "GROUNDING aid: run a SCOPED `cargo test` to confirm a specific test's current pass/fail \
             (e.g. 'does this test reproduce the bug?'). A `crate` is REQUIRED; a `test_filter` \
             narrows to matching tests. Confirms behavior by RUNNING it. Output is UNTRUSTED.",
            json!({
                "crate": {"type": "string", "description": "Workspace crate whose tests to run, e.g. 'rustynetd' (required — a full-workspace test is too heavy)"},
                "test_filter": {"type": "string", "description": "Optional test-name substring to narrow the run, e.g. 'killswitch' or 'macos_render_pf'"},
                "target": {"type": "string", "description": "'host'/'macos' (default) or 'windows' (x86_64-pc-windows-gnu)"}
            }),
            &["crate"],
        ),
    ])
}

/// The REPO-READS-ONLY subset of the tool definitions for `deepseek_doc_sync`.
/// It exposes ONLY repo-inspection tools (read_file / list_dir / grep /
/// find_files / find_definition / find_references + read-only git) — NO lab,
/// guest, host, or cargo tools — so a docs-sync proposal can only read repo
/// files. The names here MUST stay in lockstep with `DOC_SYNC_TOOL_NAMES`, which
/// the dispatch gate enforces. Built by filtering `agent_tool_definitions()` so
/// the per-tool schemas never drift from the full set.
fn doc_sync_tool_definitions() -> Value {
    let all = agent_tool_definitions();
    let filtered: Vec<Value> = all
        .as_array()
        .map(|defs| {
            defs.iter()
                .filter(|d| {
                    d["function"]["name"]
                        .as_str()
                        .is_some_and(|n| DOC_SYNC_TOOL_NAMES.contains(&n))
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    Value::Array(filtered)
}

/// Build one OpenAI-style function-tool definition object.
fn fn_tool(name: &str, description: &str, properties: Value, required: &[&str]) -> Value {
    json!({
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
            }
        }
    })
}

fn model_schema() -> Value {
    json!({
        "type": "string",
        "enum": ["flash", "pro"],
        "description": "'flash' = deepseek-v4-flash (fast, low cost, default). 'pro' = deepseek-v4-pro (chain-of-thought at max reasoning effort, slower, for hard reasoning tasks).",
    })
}

fn context_schema() -> Value {
    json_schema_string(
        "Optional context — file contents, code, docs, error output, etc. \
         Prepended to the prompt so DeepSeek has the material to work from.",
    )
}

impl McpServer for DeepSeekServer {
    fn server_info(&self) -> ServerInfo {
        ServerInfo {
            name: "rustynet-mcp-deepseek".into(),
            version: "0.1.0".into(),
        }
    }

    fn tools(&self) -> Vec<Tool> {
        vec![
            Tool {
                name: "deepseek_read".into(),
                description: "\
                    Query DeepSeek for analysis, research, explanation, or code review. \
                    Read-only intent — DeepSeek will assess and explain, not generate new artifacts. \
                    Good for: second opinions on architecture, security review, explaining unfamiliar code, \
                    comparing approaches, identifying risks in a plan."
                    .into(),
                input_schema: json_schema_object(
                    json!({
                        "prompt":  json_schema_string("The question or analysis request."),
                        "model":   model_schema(),
                        "context": context_schema(),
                    }),
                    vec!["prompt"],
                ),
            },
            Tool {
                name: "deepseek_write".into(),
                description: "\
                    Ask DeepSeek to generate or write content — Rust code, tests, documentation, \
                    config files, scripts, etc. Write intent — the primary output is content to be \
                    used or written to disk. \
                    Good for: generating boilerplate, writing test cases, drafting docs, \
                    producing config templates."
                    .into(),
                input_schema: json_schema_object(
                    json!({
                        "prompt":  json_schema_string("The generation instruction — what to write and any constraints."),
                        "model":   model_schema(),
                        "context": context_schema(),
                    }),
                    vec!["prompt"],
                ),
            },
            Tool {
                name: "deepseek_read_write".into(),
                description: "\
                    Full autonomy: DeepSeek analyzes existing content AND generates output. \
                    Use when the task requires understanding current code/state before producing changes. \
                    DeepSeek will structure its response as: analysis first, then generated output. \
                    Good for: review-then-fix, audit-then-patch, explain-then-refactor, \
                    read-a-plan-then-implement."
                    .into(),
                input_schema: json_schema_object(
                    json!({
                        "prompt":  json_schema_string("Combined instruction — what to analyze and what to produce."),
                        "model":   model_schema(),
                        "context": context_schema(),
                    }),
                    vec!["prompt"],
                ),
            },
            Tool {
                name: "deepseek_agent".into(),
                description: "\
                    READ-ONLY autonomous research agent. DeepSeek drives a tool-calling loop against a \
                    confined, read-only tool set that inspects THIS machine's local Rustynet repo and UTM \
                    lab (read_file, list_dir, grep, find_files, find_definition, read-only git, \
                    utm_vm_status, lab_inventory, lab_node_reachable, lab_guest_exec [fixed read-only \
                    any-OS guest diagnostics: Linux via utmctl, macOS/Windows via SSH], \
                    host_system_info, host_disk_status, lab_run_status, \
                    lab_run_detail, lab_jobs, lab_loop_journal, lab_job_log, lab_stage_log, \
                    lab_report_grep, lab_report_artifacts) and returns an evidence-backed answer plus an \
                    audit trace of what it inspected. It CANNOT write/edit/delete anything. \
                    Good for: 'where/how is X implemented', 'does the code actually do Y', \
                    grounded cross-file investigations, lab-state and live-lab-run drill-in questions. \
                    Use the proxy tools (deepseek_read/write/read_write) when you want to hand DeepSeek \
                    material directly instead of having it explore."
                    .into(),
                input_schema: json_schema_object(
                    json!({
                        "prompt":    json_schema_string("The research question to investigate against the local repo/lab."),
                        "model":     model_schema(),
                        "max_steps": json!({
                            "type": "integer",
                            "description": "Max tool-calling steps before forcing a final answer (default 12, cap 20).",
                        }),
                    }),
                    vec!["prompt"],
                ),
            },
            Tool {
                name: "deepseek_live_lab".into(),
                description: "\
                    Run the RIGID live-lab failure-triage pipeline. DeepSeek v4-flash researches \
                    why/where/what failed (grounded in the real local repo + UTM lab), a second \
                    v4-flash independently verifies every claim against the repo/lab, then v4-pro at \
                    MAX reasoning reviews, re-verifies, and judges the best fix — all three steps \
                    READ-ONLY, no code changes, every claim evidence-cited. Hand it the failed run's \
                    stage output / report excerpt / daemon logs (and/or a report_dir the agents can \
                    read) as 'failure_context'; it returns one verified report for you to act on. \
                    UNTRUSTED output — you verify before changing any code. Runs ASYNC (the pipeline \
                    takes minutes, longer than the MCP request timeout): returns a job_id \
                    immediately; poll 'deepseek_live_lab_result' for the report."
                    .into(),
                input_schema: json_schema_object(
                    json!({
                        "target": json_schema_string(
                            "What was under test (e.g. 'macOS relay lifecycle') — for the report header and to focus the triage."),
                        "failure_context": json_schema_string(
                            "The failed run's evidence to triage: stage output, report excerpt, daemon/journal logs, and/or a report_dir path the grounded agents can read."),
                        "max_steps": json!({
                            "type": "integer",
                            "description": "Max tool-calling steps per triage agent before forcing an answer (default 12, cap 20).",
                        }),
                    }),
                    vec!["target", "failure_context"],
                ),
            },
            Tool {
                name: "deepseek_live_lab_result".into(),
                description: "\
                    Poll an async deepseek_live_lab triage job. Non-blocking: returns the verified \
                    multi-section report once the pipeline finishes, or a 'still running' status \
                    (with elapsed seconds) to poll again. Pass the job_id returned by \
                    deepseek_live_lab."
                    .into(),
                input_schema: json_schema_object(
                    json!({
                        "job_id": json_schema_string("The job id returned by deepseek_live_lab."),
                    }),
                    vec!["job_id"],
                ),
            },
            Tool {
                name: "deepseek_lab_run".into(),
                description: "\
                    Run the WHOLE live-lab pipeline in one call: launch the hardened orchestrator for \
                    an area, wait for it, and on failure run the rigid triage pipeline automatically — \
                    you get back ONE report (PASS evidence, or root cause + file:line + suspected fix). \
                    The launch + wait are DETERMINISTIC (no LLM in the deploy path); only the triage \
                    uses DeepSeek. Async: returns a job_id immediately; poll deepseek_live_lab_result \
                    for the report (a run takes many minutes). The lab is a singleton — one run at a \
                    time. UNTRUSTED triage output — verify before changing code."
                    .into(),
                input_schema: json_schema_object(
                    json!({
                        "area": json_schema_string(
                            "What area of the lab to work on (e.g. 'macOS relay', 'Windows admin') — the report header + triage focus."),
                        "macos": json!({"type": "boolean", "description": "Include the macOS guest (auto-resolved from the inventory)."}),
                        "windows": json!({"type": "boolean", "description": "Include the Windows guest (auto-resolved from the inventory)."}),
                        "macos_vm": json_schema_string("Explicit macOS guest alias (overrides `macos` auto-resolution)."),
                        "windows_vm": json_schema_string("Explicit Windows guest alias (overrides `windows` auto-resolution)."),
                        "rebuild_nodes": json_schema_string("Comma-separated node aliases to redeploy ONLY (fast re-verify after a per-node patch)."),
                        "exit_vm": json_schema_string("Linux exit-node alias for this run's backbone (use a DISJOINT exit_vm/client_vm per run when running concurrently)."),
                        "client_vm": json_schema_string("Linux client-node alias for this run's backbone."),
                        "exit_platform": json_schema_string("ELECT this OS (linux|macos|windows) into the EXIT role so the focused mac/win exit cell runs live instead of skipping."),
                        "relay_platform": json_schema_string("ELECT this OS (linux|macos|windows) into the RELAY role so the focused mac/win relay cell runs live instead of skipping."),
                        "anchor_platform": json_schema_string("ELECT this OS (linux|macos|windows) into the ANCHOR role so the focused mac/win anchor cell runs live instead of skipping."),
                        "admin_platform": json_schema_string("ELECT this OS (linux|macos|windows) into the ADMIN role so the focused mac/win admin issue cell runs live instead of skipping."),
                        "blind_exit_platform": json_schema_string("ELECT this OS (linux|macos|windows) into the BLIND_EXIT role so the focused mac/win blind-exit cell runs live instead of skipping."),
                        "macos_promote_exit": json!({"type": "boolean", "description": "Option-B selector: elect macOS as a SECONDARY exit so the macOS exit cell runs live (drives is_macos_active_exit). Use alongside exit_vm/client_vm/entry_vm."}),
                        "entry_vm": json_schema_string("Linux entry-node alias for the Option-B exit topology (used alongside exit_vm/client_vm + macos_promote_exit)."),
                        "legacy_bash": json!({"type": "boolean", "description": "Route the Linux live suite through the legacy bash orchestrator instead of the default Rust one. OPTIONAL: both paths run the mac/win ROLE stages (activate_macos_exit_role + capture, relay/anchor lifecycle) when macos_vm + the role selector are set. The early 'no macOS nodes in topology' preflight line is a benign Linux-preflight artifact, not a skip of the macOS role stages."}),
                        "skip_linux_live_suite": json!({"type": "boolean", "description": "FAST mac/win cell iteration: skip the ~30-45 min Linux live-validation suite (anchor/role-switch/exit-handoff/relay/two-hop/managed-dns/chaos) and jump straight to the mac/win role stages AFTER setup (bootstrap + membership + signed-bundle distribution still run, because the mac/win stages need the mesh). Pair with a role-platform selector (exit_platform/relay_platform/anchor_platform/blind_exit_platform or macos_promote_exit) to drive ONE mac/win cell live without paying for the whole Linux lab. The mac/win stages gate on setup's distribute_* outcomes, not the Linux suite, so they stay fully exercised. Use this whenever you are failing on a mac/win stage and the Linux suite would just be wasted time."}),
                        "windows_only": json!({"type": "boolean", "description": "Skip ALL Linux stages (incl. membership setup) and run ONLY the Windows bootstrap + validation stages; requires windows_vm. NOTE: this also skips membership distribution, so it only works when the Windows guest is already mesh-joined from a prior run — for a fresh Windows cell use skip_linux_live_suite instead (keeps setup)."}),
                        "allow_concurrent": json!({"type": "boolean", "description": "Opt into PARALLEL runs (default false = singleton). When true, up to 3 runs may overlap — you MUST give each disjoint guests (e.g. the macOS↔Windows pipeline: macOS on one Debian backbone, Windows on another). Each concurrent run gets its own CARGO_TARGET_DIR + report dir."}),
                        "dry_run": json!({"type": "boolean", "description": "Run the orchestrator in --dry-run mode (fast; verifies the launch wiring without a real lab pass)."}),
                        "triage_on_failure": json!({"type": "boolean", "description": "Default true. When false, a failed live lab returns local report/log pointers without calling the external DeepSeek API. Use this when external triage has not been explicitly approved."}),
                        "max_steps": json!({"type": "integer", "description": "Max tool-calling steps per triage agent on failure (default 12, cap 20)."}),
                    }),
                    vec!["area"],
                ),
            },
            Tool {
                name: "deepseek_next_live_lab_target".into(),
                description: "\
                    Read-only chooser for the next live-lab target. It inspects the run matrix, \
                    prefers the latest failed stage, then release-blocking macOS/Windows role \
                    cells that are not currently pass, and returns the exact deepseek_lab_run \
                    JSON args a simple agent should call. Pass target=<key> to render an explicit \
                    target (macos_exit, windows_anchor, full, ...)."
                    .into(),
                input_schema: json_schema_object(
                    json!({
                        "target": json_schema_string("Optional explicit key: macos_admin|windows_admin|macos_exit|windows_exit|macos_blind_exit|macos_anchor|windows_anchor|macos_relay|windows_relay|full"),
                    }),
                    vec![],
                ),
            },
            Tool {
                name: "deepseek_autonomous_live_lab_loop".into(),
                description: "\
                    One-call autonomous loop step for simple agents: reconcile stale/interrupted \
                    DeepSeek labrun records, refuse to double-launch if a run is still in flight, \
                    choose the next matrix-backed live-lab target, then launch deepseek_lab_run \
                    with the right focused role selector. On pass, call again to progress to the \
                    next target; on fail, the launched run auto-triages with DeepSeek."
                    .into(),
                input_schema: json_schema_object(
                    json!({
                        "target": json_schema_string("Optional explicit key instead of matrix selection."),
                        "dry_run": json_schema_boolean("Pass through to deepseek_lab_run for wiring checks."),
                        "triage_on_failure": json_schema_boolean("Pass through to deepseek_lab_run; false disables external DeepSeek API triage on failure."),
                        "allow_concurrent": json_schema_boolean("Pass through to deepseek_lab_run; use only with disjoint guests."),
                        "max_steps": json!({"type": "integer", "description": "Max tool-calling steps per triage agent on failure."}),
                    }),
                    vec![],
                ),
            },
            Tool {
                name: "deepseek_recover_lab_environment".into(),
                description: "\
                    Async recovery function for interrupted live-lab loops. Reconciles stale \
                    DeepSeek job records, then runs the Rust orchestrator to --stop-after-ready \
                    so VMs are powered/reachable before the next labrun. Use when a prior lab was \
                    interrupted and the next launch is blocked or guests may be stale. Poll \
                    deepseek_live_lab_result with the returned recover-* job id."
                    .into(),
                input_schema: json_schema_object(
                    json!({
                        "dry_run": json_schema_boolean("Plan-only recovery wiring check."),
                        "force": json_schema_boolean("Allow recovery launch even if a labrun still appears in flight; only use after proving it is dead/interrupted."),
                    }),
                    vec![],
                ),
            },
            Tool {
                name: "deepseek_doc_sync".into(),
                description: "\
                    Propose docs-only edits to keep the repo in sync with a lab-verified fix. \
                    READ-ONLY + PROPOSE-ONLY: a grounded agent reads the CURRENT docs (active \
                    ledgers, CODE_MAP, README/AGENTS/CLAUDE, the doc indexes, run-matrix) over a \
                    repo-reads-only tool set — NO lab/guest/cargo tools — and returns a STRUCTURED \
                    list of exact edits (file / old_string / new_string / rationale, each \
                    copy-paste-applicable by exact string replacement) plus a 'considered, no \
                    change' coverage list. It writes NOTHING to disk; a human applies the edits. \
                    Docs-only (documents/** + root README.md/AGENTS.md/CLAUDE.md); enforces the \
                    AGENTS.md↔CLAUDE.md mirror and index-sync, and never invents evidence/status/ \
                    dates/SHAs. UNTRUSTED output — review before applying. Runs ASYNC: returns a \
                    job_id immediately; poll 'deepseek_live_lab_result' for the report."
                    .into(),
                input_schema: json_schema_object(
                    json!({
                        "change_summary": json_schema_string(
                            "REQUIRED: what was fixed/patched/verified — the change the docs must now reflect."),
                        "commit": json_schema_string(
                            "Optional commit SHA(s) of the fix (reflected verbatim; not invented)."),
                        "evidence": json_schema_string(
                            "Optional verifying lab run id / run-matrix row / stage that proves the fix."),
                        "doc_hints": json_schema_string(
                            "Optional hint at which docs are likely affected, e.g. 'CrossPlatformRoleParityPlan'."),
                        "model": model_schema(),
                        "max_steps": json!({
                            "type": "integer",
                            "description": "Max tool-calling steps before forcing the proposal (default 12, cap 20).",
                        }),
                    }),
                    vec!["change_summary"],
                ),
            },
            Tool {
                name: "deepseek_reconcile_jobs".into(),
                description: "\
                    Self-service repair of stale live-lab job records so a crashed or killed \
                    deepseek_lab_run can no longer block the singleton gate forever. Scans this \
                    server's persisted job records (or just `job_id` if given): a `state=running` \
                    record whose orchestrator already wrote its completion artifact is reclassified \
                    DONE (recovering the run outcome); one whose recorded orchestrator pid is dead \
                    with no artifact is reclassified CRASHED; a record that is genuinely in flight \
                    (live pid, or no pid recorded) is left running, conservatively. Returns a \
                    summary of how many were scanned, reconciled (done vs crashed), and left \
                    running. Writes only this server's own job records (atomic tmp+rename); never \
                    touches the lab, guests, or repo. Synchronous — no job_id to poll."
                    .into(),
                input_schema: json_schema_object(
                    json!({
                        "job_id": json_schema_string(
                            "Optional: reconcile only this one labrun job record. Omit to scan ALL persisted labrun records."),
                    }),
                    Vec::<&str>::new(),
                ),
            },
        ]
    }

    fn call_tool(&self, name: &str, arguments: Option<Value>) -> ToolCallResult {
        let args = match arguments {
            Some(v) => v,
            None => return tool_error("missing arguments"),
        };

        // The live-lab triage pipeline has its own arg schema (no prompt/model).
        if name == "deepseek_live_lab" {
            return self.call_live_lab(&args);
        }
        if name == "deepseek_live_lab_result" {
            return self.call_live_lab_result(&args);
        }
        if name == "deepseek_lab_run" {
            return self.call_lab_run(&args);
        }
        if name == "deepseek_next_live_lab_target" {
            return self.call_next_live_lab_target(&args);
        }
        if name == "deepseek_autonomous_live_lab_loop" {
            return self.call_autonomous_live_lab_loop(&args);
        }
        if name == "deepseek_recover_lab_environment" {
            return self.call_recover_lab_environment(&args);
        }
        if name == "deepseek_doc_sync" {
            return self.call_doc_sync(&args);
        }
        if name == "deepseek_reconcile_jobs" {
            return self.call_reconcile_jobs(&args);
        }

        let prompt = match get_str(&args, "prompt") {
            Some(p) if !p.trim().is_empty() => p,
            _ => return tool_error("'prompt' is required and must not be empty"),
        };
        let model_str = get_str(&args, "model").unwrap_or("flash");
        let model = resolve_model(model_str);

        // The autonomous agent has its own loop + system prompt.
        if name == "deepseek_agent" {
            let max_steps = args
                .get("max_steps")
                .and_then(|v| v.as_u64())
                .map(|n| n.clamp(1, AGENT_HARD_MAX_STEPS))
                .unwrap_or(AGENT_DEFAULT_MAX_STEPS);
            return match self.run_agent(prompt, model, max_steps) {
                Ok(answer) => {
                    let header = format!("[deepseek/{model} | AGENT | budget={max_steps}]\n\n");
                    ToolCallResult {
                        content: text_content(format!("{header}{answer}")),
                        is_error: None,
                    }
                }
                Err(e) => tool_error(&e),
            };
        }

        let context = get_str(&args, "context");

        let (system, intent_label) = match name {
            "deepseek_read" => (
                "You are a senior Rust engineer and security-focused systems architect. \
                 Analyze the provided content and answer clearly and concisely. \
                 Focus on insight, explanation, risk assessment, and correctness — \
                 do not generate new code or artifacts unless the user explicitly asks. \
                 Be direct and precise. Flag security concerns prominently.",
                "READ",
            ),
            "deepseek_write" => (
                "You are a senior Rust engineer. Generate the requested code, documentation, \
                 or content. Be precise, idiomatic, and production-quality. \
                 Follow Rust best practices: no unwrap in non-test paths, proper error propagation, \
                 no unsafe unless unavoidable and justified. \
                 Return the generated content with brief inline comments only where the WHY \
                 is non-obvious.",
                "WRITE",
            ),
            "deepseek_read_write" => (
                "You are a senior Rust engineer and security-focused systems architect. \
                 First analyze the provided content thoroughly, then generate the requested \
                 output. Structure your response in two clearly separated sections: \
                 ## Analysis (your findings, risks, decisions) \
                 ## Output (the generated code/content/changes). \
                 Be precise, idiomatic, and security-conscious.",
                "READ+WRITE",
            ),
            _ => return tool_error(&format!("unknown tool: {name}")),
        };

        let user_prompt = build_user_prompt(intent_label, prompt, context);

        match self.call(system, &user_prompt, model) {
            Ok(response) => {
                let header = format!("[deepseek/{model} | {intent_label}]\n\n");
                ToolCallResult {
                    content: text_content(format!("{header}{response}")),
                    is_error: None,
                }
            }
            Err(e) => tool_error(&e),
        }
    }
}

fn main() {
    let server = DeepSeekServer::new();
    run_server(server);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server() -> DeepSeekServer {
        DeepSeekServer::new()
    }

    #[test]
    fn confine_rejects_traversal() {
        let s = server();
        assert!(s.confine("../etc/passwd").is_err());
        assert!(s.confine("crates/../../etc/passwd").is_err());
    }

    #[test]
    fn confine_rejects_absolute() {
        let s = server();
        assert!(s.confine("/etc/passwd").is_err());
    }

    #[test]
    fn confine_accepts_repo_file() {
        let s = server();
        // Cargo.toml exists at repo root in this workspace.
        assert!(s.confine("Cargo.toml").is_ok());
    }

    #[test]
    fn read_file_stays_in_repo() {
        let s = server();
        let out = s.tool_read_file(&json!({"path": "Cargo.toml"})).unwrap();
        assert!(
            out.contains("workspace") || out.contains("[workspace]") || out.contains("members")
        );
        // Escape attempt fails.
        assert!(
            s.tool_read_file(&json!({"path": "../../../etc/passwd"}))
                .is_err()
        );
    }

    #[test]
    fn read_file_caps_bytes() {
        let s = server();
        let out = s
            .tool_read_file(&json!({"path": "Cargo.toml", "max_bytes": 16}))
            .unwrap();
        // 16 bytes of content + the header + truncation note: still tiny.
        assert!(
            out.len() < 400,
            "expected a capped read, got {} bytes",
            out.len()
        );
    }

    #[test]
    fn list_dir_lists_repo_root() {
        let s = server();
        let out = s.tool_list_dir(&json!({"path": "."})).unwrap();
        assert!(out.contains("Cargo.toml"));
        assert!(out.contains("crates"));
    }

    #[test]
    fn git_rejects_mutating_subcommands() {
        let s = server();
        for sub in [
            "commit", "push", "checkout", "add", "reset", "rm", "clean", "stash",
        ] {
            let err = s.tool_git(&json!({"args": [sub]}));
            assert!(err.is_err(), "git {sub} must be rejected");
        }
    }

    #[test]
    fn git_rejects_branch_delete_flag() {
        let s = server();
        assert!(s.tool_git(&json!({"args": ["branch", "-d", "x"]})).is_err());
        assert!(s.tool_git(&json!({"args": ["tag", "-d", "x"]})).is_err());
    }

    #[test]
    fn git_rejects_write_and_exec_flags() {
        let s = server();
        // --output writes a file; -O/--open-files-in-pager, --ext-diff, --textconv
        // exec an external command — all rejected even on allowlisted subcommands.
        for args in [
            json!({"args": ["diff", "--output=/tmp/escape"]}),
            json!({"args": ["diff", "--output", "/tmp/escape"]}),
            json!({"args": ["grep", "-Oless", "x"]}),
            json!({"args": ["grep", "--open-files-in-pager=less", "x"]}),
            json!({"args": ["log", "--ext-diff"]}),
            json!({"args": ["grep", "--textconv", "x"]}),
            json!({"args": ["cat-file", "--filters", "HEAD:Cargo.toml"]}),
        ] {
            assert!(
                s.tool_git(&args).is_err(),
                "must reject write/exec git flags: {args}"
            );
        }
        // A benign read-only flag on the same subcommand stays allowed.
        assert!(
            s.tool_git(&json!({"args": ["log", "--oneline", "-1"]}))
                .is_ok()
        );
    }

    #[test]
    fn git_allows_rev_parse() {
        let s = server();
        // rev-parse is allowlisted; in a git repo it returns the HEAD sha.
        let out = s
            .tool_git(&json!({"args": ["rev-parse", "--abbrev-ref", "HEAD"]}))
            .unwrap();
        assert!(out.starts_with("# git rev-parse"));
    }

    #[test]
    fn grep_finds_known_token() {
        let s = server();
        // Pattern is a regex (rg/grep -e), so use a literal token without
        // regex metacharacters. `DeepSeekServer` is defined in this file.
        let out = s
            .tool_grep(&json!({"pattern": "DeepSeekServer", "path": "crates/rustynet-mcp/src"}))
            .unwrap();
        assert!(out.contains("deepseek.rs"));
        // Paths are repo-relative, not absolute.
        assert!(
            !out.contains("/Users/"),
            "grep output should be repo-relative"
        );
    }

    #[test]
    fn is_valid_host_accepts_ip_and_hostname() {
        assert!(is_valid_host("192.168.64.10"));
        assert!(is_valid_host("::1"));
        assert!(is_valid_host("debian-1"));
        assert!(is_valid_host("node.lab.local"));
    }

    #[test]
    fn is_valid_host_rejects_metachars() {
        assert!(!is_valid_host(""));
        assert!(!is_valid_host("host; rm -rf /"));
        assert!(!is_valid_host("$(whoami)"));
        assert!(!is_valid_host("a b"));
        assert!(!is_valid_host("a|b"));
        assert!(!is_valid_host("-leadinghyphen"));
    }

    #[test]
    fn lab_node_reachable_unresolvable_is_not_error() {
        let s = server();
        // A syntactically valid but unresolvable host returns a result, not an error.
        let out = s
            .tool_lab_node_reachable(&json!({"host": "no-such-host.invalid", "port": 22}))
            .unwrap();
        assert!(out.contains("reachable"));
    }

    #[test]
    fn lab_node_reachable_rejects_bad_host() {
        let s = server();
        assert!(
            s.tool_lab_node_reachable(&json!({"host": "a; ls", "port": 22}))
                .is_err()
        );
    }

    #[test]
    fn host_system_info_reports_os_arch() {
        let s = server();
        let out = s.tool_host_system_info().unwrap();
        assert!(out.contains("os (compile-time)"));
        assert!(out.contains(std::env::consts::ARCH));
    }

    #[test]
    fn agent_tool_definitions_are_well_formed() {
        let defs = agent_tool_definitions();
        let arr = defs.as_array().unwrap();
        assert_eq!(arr.len(), 23);
        for d in arr {
            assert_eq!(d["type"], "function");
            assert!(d["function"]["name"].is_string());
            assert!(d["function"]["parameters"]["type"] == "object");
        }
        // Every advertised tool must be dispatchable (no advertise/dispatch drift).
        let names: Vec<&str> = arr
            .iter()
            .map(|d| d["function"]["name"].as_str().unwrap())
            .collect();
        for n in [
            "read_file",
            "list_dir",
            "grep",
            "git",
            "utm_vm_status",
            "lab_node_reachable",
            "host_system_info",
            "lab_run_status",
            "lab_loop_journal",
            "lab_inventory",
            "lab_jobs",
            "lab_run_detail",
            "find_files",
            "host_disk_status",
            "lab_guest_exec",
            "lab_job_log",
            "lab_stage_log",
            "lab_report_grep",
            "lab_report_artifacts",
            "find_definition",
            "find_references",
            "cargo_check",
            "cargo_test",
        ] {
            assert!(names.contains(&n), "tool {n} missing from definitions");
        }
    }

    #[test]
    fn agent_tool_set_excludes_deepseek_proxy_tools() {
        // The read/write/read_write/agent proxies + the live-lab orchestrator are
        // top-level MCP tools the *main agent* drives — a DeepSeek agent must never
        // be able to recursively call them from inside its own tool-calling loop.
        let defs = agent_tool_definitions();
        let names: Vec<&str> = defs
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["function"]["name"].as_str().unwrap())
            .collect();
        for forbidden in [
            "deepseek_read",
            "deepseek_write",
            "deepseek_read_write",
            "deepseek_agent",
            "deepseek_live_lab",
            "deepseek_live_lab_result",
            "deepseek_lab_run",
            "deepseek_next_live_lab_target",
            "deepseek_autonomous_live_lab_loop",
            "deepseek_recover_lab_environment",
            "deepseek_reconcile_jobs",
        ] {
            assert!(
                !names.contains(&forbidden),
                "proxy/top-level tool {forbidden} must NOT be in the agent tool-set"
            );
        }
    }

    #[test]
    fn doc_sync_tool_set_is_repo_reads_only() {
        // The docs-sync tool set is the REPO-READS-ONLY subset: only repo-read
        // tools + read-only git. It must expose NO lab/guest/host/cargo tool, so a
        // docs-sync run can touch no lab or guest surface at all.
        let defs = doc_sync_tool_definitions();
        let names: Vec<&str> = defs
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["function"]["name"].as_str().unwrap())
            .collect();

        // Exactly the allowed names, and nothing else.
        for expected in DOC_SYNC_TOOL_NAMES {
            assert!(
                names.contains(expected),
                "docs-sync set missing repo-read tool {expected}"
            );
        }
        assert_eq!(
            names.len(),
            DOC_SYNC_TOOL_NAMES.len(),
            "docs-sync set has an unexpected tool: {names:?}"
        );

        // No lab/guest/host/cargo tool may leak in.
        for forbidden in [
            "lab_guest_exec",
            "lab_node_reachable",
            "utm_vm_status",
            "host_system_info",
            "host_disk_status",
            "lab_run_status",
            "lab_run_detail",
            "lab_jobs",
            "lab_loop_journal",
            "lab_inventory",
            "lab_job_log",
            "lab_stage_log",
            "lab_report_grep",
            "lab_report_artifacts",
            "cargo_check",
            "cargo_test",
        ] {
            assert!(
                !names.contains(&forbidden),
                "docs-sync set must NOT expose lab/guest/cargo tool {forbidden}"
            );
        }

        // Every docs-sync definition is also in the full set (so schemas never
        // drift) and is well-formed.
        let full: Vec<String> = agent_tool_definitions()
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["function"]["name"].as_str().unwrap().to_string())
            .collect();
        for d in defs.as_array().unwrap() {
            let func = &d["function"];
            let name = func["name"].as_str().unwrap();
            assert!(
                full.iter().any(|n| n == name),
                "docs-sync tool {name} is not derived from the full set"
            );
            assert!(func["description"].is_string());
            assert!(func["parameters"]["properties"].is_object());
        }
    }

    #[test]
    fn doc_sync_toolset_gate_rejects_non_repo_tools() {
        // The dispatch gate must allow ONLY the repo-read tools for docs-sync and
        // refuse any lab/guest/cargo tool, even if the model emits its name.
        for allowed in DOC_SYNC_TOOL_NAMES {
            assert!(
                AgentToolset::DocsRepoReadOnly.allows(allowed),
                "docs-sync gate must allow {allowed}"
            );
        }
        for forbidden in [
            "lab_guest_exec",
            "lab_inventory",
            "utm_vm_status",
            "cargo_check",
            "cargo_test",
            "host_disk_status",
        ] {
            assert!(
                !AgentToolset::DocsRepoReadOnly.allows(forbidden),
                "docs-sync gate must reject {forbidden}"
            );
            // The full agent set, by contrast, allows everything.
            assert!(AgentToolset::Full.allows(forbidden));
        }
    }

    #[test]
    fn doc_sync_requires_change_summary() {
        let s = server();
        // Missing / blank change_summary → error result (so the caller can fix it),
        // and no job is spawned.
        assert!(s.call_doc_sync(&json!({})).is_error.is_some());
        assert!(
            s.call_doc_sync(&json!({"change_summary": "   "}))
                .is_error
                .is_some()
        );
    }

    #[test]
    fn strip_dsml_markup_removes_native_tool_markup() {
        let s = "Here is my conclusion.\n<\u{ff5c}\u{ff5c}DSML\u{ff5c}\u{ff5c}tool_calls>\njunk";
        assert_eq!(strip_dsml_markup(s), "Here is my conclusion.");
        // Clean prose is unchanged (trimmed).
        assert_eq!(strip_dsml_markup("  clean answer  "), "clean answer");
        // Pure markup → empty, so the caller substitutes a budget note.
        assert_eq!(
            strip_dsml_markup("<\u{ff5c}\u{ff5c}DSML\u{ff5c}\u{ff5c}tool_calls>x"),
            ""
        );
    }

    #[test]
    fn live_lab_result_polls_job_state() {
        let s = server();
        // Missing / unknown job id → error result (so the caller can recover).
        assert!(s.call_live_lab_result(&json!({})).is_error.is_some());
        assert!(
            s.call_live_lab_result(&json!({"job_id": "nope"}))
                .is_error
                .is_some()
        );
        // A finished job → non-error result carrying the report.
        s.jobs.lock().unwrap().insert(
            "triage-1".to_string(),
            TriageJob::Done("THE REPORT".to_string()),
        );
        assert!(
            s.call_live_lab_result(&json!({"job_id": "triage-1"}))
                .is_error
                .is_none()
        );
        // A running job → non-error "still running" status.
        s.jobs.lock().unwrap().insert(
            "triage-2".to_string(),
            TriageJob::Running {
                started: Instant::now(),
            },
        );
        assert!(
            s.call_live_lab_result(&json!({"job_id": "triage-2"}))
                .is_error
                .is_none()
        );
    }

    #[test]
    fn lab_run_concurrency_gate_rejects_at_limit() {
        // Reject paths only — they return before spawning a real orchestrator.
        let s = server();
        // One run in flight → the default (singleton) rejects a second.
        s.jobs.lock().unwrap().insert(
            "labrun-1".into(),
            TriageJob::Running {
                started: Instant::now(),
            },
        );
        assert!(
            s.call_lab_run(&json!({"area": "x"})).is_error.is_some(),
            "singleton must reject a 2nd run"
        );
        // Fill to the concurrent cap → even allow_concurrent rejects past it.
        for i in 2..=MAX_CONCURRENT_LAB_RUNS {
            s.jobs.lock().unwrap().insert(
                format!("labrun-{i}"),
                TriageJob::Running {
                    started: Instant::now(),
                },
            );
        }
        assert!(
            s.call_lab_run(&json!({"area": "x", "allow_concurrent": true}))
                .is_error
                .is_some(),
            "allow_concurrent must still reject once at the cap"
        );
    }

    #[test]
    fn orchestrator_args_are_safe_and_well_formed() {
        let a = build_orchestrator_args(
            "documents/operations/active/vm_lab_inventory.json",
            "/home/u/.ssh/id",
            "/home/u/.ssh/known_hosts",
            "state/deepseek-lab-labrun-1",
            Some("macos-utm-1"),
            None,
            Some("debian-2"),
            None,
            Some("ll-3"),
            Some("macos"),    // exit_platform
            None,             // relay_platform
            None,             // anchor_platform
            Some("macos"),    // admin_platform
            None,             // blind_exit_platform
            Some("debian-3"), // entry_vm
            true,             // macos_promote_exit
            true,             // legacy_bash
            false,            // dry_run
            false,            // windows_only
            true,             // skip_linux_live_suite
        );
        assert_eq!(a[0], "vm-lab-orchestrate-live-lab");
        for flag in [
            "--trust-inventory-ready",
            "--skip-gates",
            "--skip-soak",
            "--skip-cross-network",
        ] {
            assert!(a.iter().any(|x| x == flag), "missing {flag}: {a:?}");
        }
        assert!(a.windows(2).any(|w| w == ["--source-mode", "working-tree"]));
        assert!(a.windows(2).any(|w| w == ["--macos-vm", "macos-utm-1"]));
        assert!(a.windows(2).any(|w| w == ["--exit-vm", "debian-2"]));
        assert!(a.windows(2).any(|w| w == ["--rebuild-nodes", "ll-3"]));
        // Role-platform selectors present when provided.
        assert!(a.windows(2).any(|w| w == ["--exit-platform", "macos"]));
        assert!(a.windows(2).any(|w| w == ["--admin-platform", "macos"]));
        assert!(a.windows(2).any(|w| w == ["--entry-vm", "debian-3"]));
        assert!(a.iter().any(|x| x == "--macos-promote-exit"));
        assert!(a.iter().any(|x| x == "--legacy-bash-orchestrator"));
        assert!(a.iter().any(|x| x == "--skip-linux-live-suite"));
        // Selectors NOT provided do not appear.
        assert!(!a.iter().any(|x| x == "--windows-vm"));
        assert!(!a.iter().any(|x| x == "--client-vm"));
        assert!(!a.iter().any(|x| x == "--relay-platform"));
        assert!(!a.iter().any(|x| x == "--anchor-platform"));
        assert!(!a.iter().any(|x| x == "--blind-exit-platform"));
        assert!(!a.iter().any(|x| x == "--dry-run"));
        // dry_run adds the flag; no macOS/Windows/backbone/rebuild/role-platform
        // selectors (incl. --macos-promote-exit) when omitted.
        let d = build_orchestrator_args(
            "inv", "s", "k", "r", None, None, None, None, None, None, None, None, None, None, None,
            false, false, true, false, false,
        );
        assert!(d.iter().any(|x| x == "--dry-run"));
        assert!(!d.iter().any(|x| x == "--macos-vm"));
        assert!(!d.iter().any(|x| x == "--exit-vm"));
        assert!(!d.iter().any(|x| x == "--exit-platform"));
        assert!(!d.iter().any(|x| x == "--admin-platform"));
        assert!(!d.iter().any(|x| x == "--entry-vm"));
        assert!(!d.iter().any(|x| x == "--macos-promote-exit"));
        assert!(!d.iter().any(|x| x == "--legacy-bash-orchestrator"));
        assert!(!d.iter().any(|x| x == "--skip-linux-live-suite"));
    }

    #[test]
    fn triage_report_has_all_three_sections_in_order() {
        let r = assemble_triage_report("RESEARCH_BODY", "VERIFY_BODY", "REVIEW_BODY");
        assert!(
            r.contains("RESEARCH_BODY") && r.contains("VERIFY_BODY") && r.contains("REVIEW_BODY")
        );
        // Rigid pipeline order: research before verify before review.
        let (ir, iv, ire) = (
            r.find("RESEARCH_BODY").unwrap(),
            r.find("VERIFY_BODY").unwrap(),
            r.find("REVIEW_BODY").unwrap(),
        );
        assert!(
            ir < iv && iv < ire,
            "sections must be research -> verify -> review"
        );
        // Labels the models + the read-only/untrusted posture.
        assert!(r.contains("deepseek-v4-flash") && r.contains("deepseek-v4-pro"));
        assert!(r.to_lowercase().contains("untrusted"));
    }

    #[test]
    fn parse_csv_line_handles_quoted_fields() {
        let f = parse_csv_line(r#"a,"b,c","d""e",f"#);
        assert_eq!(
            f,
            vec![
                "a".to_string(),
                "b,c".to_string(),
                "d\"e".to_string(),
                "f".to_string()
            ]
        );
    }

    #[test]
    fn lab_run_status_reads_the_matrix() {
        // The run matrix is a tracked repo file → summarize it (or cleanly report
        // not-found); never error or escape the repo.
        let s = server();
        let out = s
            .tool_lab_run_status(&json!({"limit": 3}))
            .expect("lab_run_status ok");
        assert!(out.contains("run matrix"));
    }

    #[test]
    fn lab_loop_journal_is_read_only_and_safe() {
        // Present (runtime) or absent (CI) — either way Ok, never error/escape.
        let s = server();
        let out = s
            .tool_lab_loop_journal(&json!({"limit": 2}))
            .expect("lab_loop_journal ok");
        assert!(out.contains("journal"));
    }

    #[test]
    fn dispatch_unknown_tool_returns_error_text() {
        let s = server();
        let out = s.dispatch_agent_tool("definitely_not_a_tool", &json!({}));
        assert!(out.starts_with("ERROR:"));
    }

    #[test]
    fn find_files_finds_a_known_file() {
        let s = server();
        // Cargo.toml exists at the repo root in this workspace.
        let out = s
            .tool_find_files(&json!({"pattern": "Cargo.toml"}))
            .expect("find_files ok");
        assert!(out.contains("Cargo.toml"));
        // Paths are repo-relative, not absolute.
        assert!(
            !out.contains("/Users/"),
            "find_files output should be repo-relative"
        );
    }

    #[test]
    fn find_files_rejects_empty_pattern() {
        let s = server();
        assert!(s.tool_find_files(&json!({"pattern": ""})).is_err());
        assert!(s.tool_find_files(&json!({})).is_err());
    }

    #[test]
    fn lab_inventory_reads_or_reports_absent() {
        // The inventory is a tracked repo file → summarize it (or cleanly report
        // not-found); never error or escape the repo.
        let s = server();
        let out = s.tool_lab_inventory().expect("lab_inventory ok");
        assert!(out.contains("inventory"));
    }

    #[test]
    fn lab_jobs_is_read_only_and_safe() {
        // Present (runtime) or absent (CI) — either way Ok, never error/escape.
        let s = server();
        let out = s.tool_lab_jobs(&json!({"limit": 3})).expect("lab_jobs ok");
        assert!(out.contains("jobs"));
    }

    #[test]
    fn lab_run_detail_handles_present_or_absent() {
        let s = server();
        // A confined-but-nonexistent report dir is rejected (not an escape).
        assert!(
            s.tool_lab_run_detail(&json!({"report_dir": "state/no-such-run-dir-xyz"}))
                .is_err()
        );
        // Missing required arg.
        assert!(s.tool_lab_run_detail(&json!({})).is_err());
        // Traversal escape is rejected.
        assert!(
            s.tool_lab_run_detail(&json!({"report_dir": "../../etc"}))
                .is_err()
        );
        // A real report dir (when present) summarizes cleanly.
        let live = s.repo_root.join("state");
        if live.is_dir()
            && let Ok(read) = std::fs::read_dir(&live)
            && let Some(run) = read.flatten().find_map(|e| {
                let p = e.path();
                p.join("state/stages.tsv")
                    .is_file()
                    .then(|| p.file_name().map(|n| n.to_string_lossy().to_string()))
                    .flatten()
            })
        {
            let rel = format!("state/{run}");
            let out = s
                .tool_lab_run_detail(&json!({"report_dir": rel}))
                .expect("lab_run_detail ok on a real run dir");
            assert!(out.contains("run detail"));
        }
    }

    #[test]
    fn host_disk_status_reports_usage() {
        let s = server();
        let out = s.tool_host_disk_status().expect("host_disk_status ok");
        assert!(out.contains("disk status"));
    }

    #[test]
    fn lab_guest_exec_rejects_bad_alias() {
        let s = server();
        // Shell-metachar / traversal / whitespace aliases must be rejected BEFORE
        // any inventory lookup or utmctl exec.
        for bad in ["a;b", "../x", "a b", "a|b", "$(whoami)", ""] {
            let err = s.tool_lab_guest_exec(&json!({"vm_alias": bad, "check": "network"}));
            assert!(err.is_err(), "vm_alias '{bad}' must be rejected");
        }
    }

    #[test]
    fn lab_guest_exec_rejects_bad_check() {
        let s = server();
        // A syntactically valid alias but an out-of-enum check must be rejected.
        // Use a structurally valid alias; the check is validated before exec.
        let err = s.tool_lab_guest_exec(&json!({"vm_alias": "debian-1", "check": "rm -rf /"}));
        assert!(err.is_err());
        let err2 = s.tool_lab_guest_exec(&json!({"vm_alias": "debian-1", "check": "arbitrary"}));
        assert!(err2.is_err());
        // Missing check is rejected.
        assert!(
            s.tool_lab_guest_exec(&json!({"vm_alias": "debian-1"}))
                .is_err()
        );
    }

    // ── New drill-in tools ──────────────────────────────────────────────

    #[test]
    fn lab_job_log_absent_is_clean_message() {
        let s = server();
        // A well-formed job_id with no log on disk → Ok with an explanatory
        // message, never an error or an escape.
        let out = s
            .tool_lab_job_log(&json!({"job_id": "ll-0-0-0", "tail": 5}))
            .expect("lab_job_log ok");
        assert!(out.contains("job log"));
        assert!(out.contains("no log") || out.contains("```"));
    }

    #[test]
    fn lab_job_log_rejects_bad_job_id() {
        let s = server();
        // Traversal / shell-metachar / '.' / '/' job_ids must be rejected BEFORE
        // a path is built — '.' and '/' are not in the job-id charset.
        for bad in [
            "../etc/passwd",
            "a/b",
            "a;b",
            "a b",
            "a.json",
            "$(whoami)",
            "",
        ] {
            assert!(
                s.tool_lab_job_log(&json!({"job_id": bad})).is_err(),
                "job_id '{bad}' must be rejected"
            );
        }
        // Missing job_id is rejected.
        assert!(s.tool_lab_job_log(&json!({})).is_err());
    }

    #[test]
    fn lab_job_log_reads_a_real_log() {
        let s = server();
        // If a real job log exists, the tail reads it; otherwise the absent path
        // returns Ok. Either way: Ok, repo-confined, never an escape.
        let jobs = s.repo_root.join(JOBS_SUBDIR);
        if let Ok(read) = std::fs::read_dir(&jobs)
            && let Some(job_id) = read.flatten().find_map(|e| {
                let p = e.path();
                (p.extension().map(|x| x == "log").unwrap_or(false))
                    .then(|| p.file_stem().map(|n| n.to_string_lossy().to_string()))
                    .flatten()
            })
        {
            let out = s
                .tool_lab_job_log(&json!({"job_id": job_id, "tail": 3}))
                .expect("lab_job_log ok on a real log");
            assert!(out.contains("job log"));
        }
    }

    #[test]
    fn lab_stage_log_confines_report_dir() {
        let s = server();
        // Traversal / absolute report_dir is rejected.
        assert!(
            s.tool_lab_stage_log(&json!({"report_dir": "../../etc", "stage": "anchor"}))
                .is_err()
        );
        assert!(
            s.tool_lab_stage_log(&json!({"report_dir": "/etc", "stage": "anchor"}))
                .is_err()
        );
        // Confined-but-nonexistent report dir is rejected (confine requires it to exist).
        assert!(
            s.tool_lab_stage_log(
                &json!({"report_dir": "state/no-such-run-xyz", "stage": "anchor"})
            )
            .is_err()
        );
        // Missing args rejected.
        assert!(s.tool_lab_stage_log(&json!({})).is_err());
        assert!(
            s.tool_lab_stage_log(&json!({"report_dir": "."})).is_err(),
            "missing stage must be rejected"
        );
    }

    #[test]
    fn lab_stage_log_rejects_bad_stage() {
        let s = server();
        // Bad-charset stage names (traversal / metachars) are rejected. '.' is a
        // valid existing dir → confine passes, so the rejection is the stage check.
        for bad in ["../x", "a;b", "a/b", "a b", "a.b"] {
            assert!(
                s.tool_lab_stage_log(&json!({"report_dir": ".", "stage": bad}))
                    .is_err(),
                "stage '{bad}' must be rejected"
            );
        }
    }

    #[test]
    fn lab_report_grep_confines_and_validates() {
        let s = server();
        // Traversal / absolute report_dir rejected.
        assert!(
            s.tool_lab_report_grep(&json!({"report_dir": "/etc", "pattern": "x"}))
                .is_err()
        );
        assert!(
            s.tool_lab_report_grep(&json!({"report_dir": "../../etc", "pattern": "x"}))
                .is_err()
        );
        // Empty / NUL pattern rejected.
        assert!(
            s.tool_lab_report_grep(&json!({"report_dir": ".", "pattern": ""}))
                .is_err()
        );
        assert!(
            s.tool_lab_report_grep(&json!({"report_dir": ".", "pattern": "a\0b"}))
                .is_err()
        );
        // Missing args rejected.
        assert!(s.tool_lab_report_grep(&json!({})).is_err());
        // A real, confined dir greps cleanly (repo root '.' always exists). The
        // pattern reaches rg/grep as a separate argv element, never a shell string.
        let out = s
            .tool_lab_report_grep(&json!({"report_dir": "crates/rustynet-mcp/src", "pattern": "DeepSeekServer", "max": 5}))
            .expect("lab_report_grep ok");
        assert!(out.contains("report grep"));
    }

    #[test]
    fn lab_report_artifacts_lists_or_rejects() {
        let s = server();
        // Traversal / absolute rejected.
        assert!(
            s.tool_lab_report_artifacts(&json!({"report_dir": "/etc"}))
                .is_err()
        );
        assert!(
            s.tool_lab_report_artifacts(&json!({"report_dir": "../../etc"}))
                .is_err()
        );
        // Missing arg rejected.
        assert!(s.tool_lab_report_artifacts(&json!({})).is_err());
        // A real confined dir lists artifacts (repo-relative).
        let out = s
            .tool_lab_report_artifacts(&json!({"report_dir": "crates/rustynet-mcp/src/bin"}))
            .expect("lab_report_artifacts ok");
        assert!(out.contains("Report artifacts"));
        assert!(out.contains("deepseek.rs"));
        assert!(
            !out.contains("/Users/"),
            "artifact listing should be report-relative"
        );
    }

    #[test]
    fn find_definition_finds_a_known_symbol() {
        let s = server();
        // DeepSeekServer is a struct defined in this file. find_definition either
        // locates it (rg present) or returns a clear rg-absent message — both Ok.
        let out = s
            .tool_find_definition(&json!({"symbol": "DeepSeekServer"}))
            .expect("find_definition ok");
        assert!(out.contains("find_definition"));
        if !out.contains("not on PATH") {
            assert!(out.contains("deepseek.rs"));
            // Repo-relative, not absolute.
            assert!(
                !out.contains("/Users/"),
                "find_definition output should be repo-relative"
            );
        }
    }

    #[test]
    fn find_definition_rejects_regex_injection() {
        let s = server();
        // Non-identifier symbols (regex metachars / shell metachars / traversal)
        // are rejected BEFORE the symbol is spliced into the fixed regex template.
        for bad in ["a;b", ".*", "a b", "a(b)", "../x", "a|b", "a\\b", ""] {
            assert!(
                s.tool_find_definition(&json!({"symbol": bad})).is_err(),
                "symbol '{bad}' must be rejected"
            );
        }
        // Missing symbol rejected.
        assert!(s.tool_find_definition(&json!({})).is_err());
    }

    #[test]
    fn confine_resolved_rejects_out_of_tree() {
        let s = server();
        // An absolute path outside repo_root is rejected (canonicalize + prefix).
        assert!(
            s.confine_resolved(std::path::Path::new("/etc/hosts"))
                .is_none()
        );
        assert!(s.confine_resolved(std::path::Path::new("/")).is_none());
        // An in-repo absolute path canonicalizes under the root → accepted.
        let in_repo = s.repo_root.join("Cargo.toml");
        if in_repo.exists() {
            assert!(s.confine_resolved(&in_repo).is_some());
        }
    }

    #[test]
    #[cfg(unix)]
    fn collect_repo_files_does_not_follow_symlinks() {
        // Regression (adversarial-review finding): a symlink inside a confined
        // report dir must NOT be followed out of the tree. collect_repo_files
        // underpins lab_report_artifacts + lab_stage_log's fallback; before the
        // fix it followed symlinked files/dirs (is_dir()/metadata()) and leaked
        // out-of-tree names and (via lab_stage_log) contents.
        use std::os::unix::fs::symlink;

        let root =
            std::env::temp_dir().join(format!("deepseek_symlink_test_{}", std::process::id()));
        let inside = root.join("inside");
        let outside = root.join("outside");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&inside).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        // A real in-tree artifact.
        std::fs::write(inside.join("real.log"), b"in-tree").unwrap();
        // An out-of-tree secret + a symlink to it placed inside the walked dir,
        // plus a symlinked directory pointing out of the walked dir.
        let secret_file = outside.join("secret.txt");
        std::fs::write(&secret_file, b"SECRET-OUTSIDE").unwrap();
        symlink(&secret_file, inside.join("leak.txt")).unwrap();
        symlink(&outside, inside.join("leakdir")).unwrap();

        let mut files: Vec<(String, u64)> = Vec::new();
        collect_repo_files(&inside, &inside, &mut files, 0);
        let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();

        assert!(
            names.iter().any(|n| n.contains("real.log")),
            "real in-tree file must be listed: {names:?}"
        );
        assert!(
            !names
                .iter()
                .any(|n| n.contains("leak.txt") || n.contains("secret")),
            "symlinked file must NOT be followed/listed: {names:?}"
        );
        assert!(
            !names.iter().any(|n| n.contains("leakdir")),
            "symlinked dir must NOT be walked: {names:?}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A server rooted at a throwaway temp dir, so job-record writes land in the
    /// temp tree (never the real repo's state/). Mirrors `new()` but overrides
    /// `repo_root`.
    fn server_rooted(root: &Path) -> DeepSeekServer {
        let agent = ureq::AgentBuilder::new().build();
        DeepSeekServer {
            api_key: String::new(),
            agent,
            repo_root: root.to_path_buf(),
            jobs: Arc::new(Mutex::new(HashMap::new())),
            job_seq: Arc::new(AtomicU64::new(0)),
        }
    }

    #[test]
    fn new_job_id_is_unique_and_prefixed() {
        let s = server();
        let a = s.new_job_id("labrun");
        let b = s.new_job_id("labrun");
        // The prefix must remain the FIRST token (drive_deepseek.py's JOB_RE and
        // the lab_run_status filter key on it).
        assert!(a.starts_with("labrun-"), "got {a}");
        assert!(b.starts_with("labrun-"), "got {b}");
        // The trailing sequence differs, so two ids in one lifetime never collide.
        assert_ne!(a, b);
        // Other prefixes are honored too.
        assert!(s.new_job_id("triage").starts_with("triage-"));
        assert!(s.new_job_id("docsync").starts_with("docsync-"));
    }

    #[test]
    fn persisted_done_job_round_trips_after_reload() {
        // A done record written by one server instance must be readable — and
        // surfaced by deepseek_live_lab_result — from a FRESH instance whose
        // in-memory map is empty (the reload-survival contract).
        let root = std::env::temp_dir().join(format!(
            "deepseek_jobrec_done_{}_{}",
            std::process::id(),
            now_unix()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        let writer = server_rooted(&root);
        let job_id = writer.new_job_id("triage");
        writer.write_job_record(
            &job_id,
            &json!({
                "job_id": job_id,
                "kind": "triage",
                "state": "running",
                "area": "macOS relay",
                "started_unix": now_unix(),
            }),
        );
        writer.finish_job(&job_id, "THE DONE REPORT".to_string());

        // Fresh instance = empty in-memory map, same repo_root → must read disk.
        let reader = server_rooted(&root);
        assert!(
            reader.jobs.lock().unwrap().is_empty(),
            "fresh instance must start with an empty in-memory map"
        );
        let rec = reader.read_job_record(&job_id).expect("record on disk");
        assert_eq!(rec.get("state").and_then(|s| s.as_str()), Some("done"));
        assert_eq!(
            rec.get("report_text").and_then(|s| s.as_str()),
            Some("THE DONE REPORT")
        );
        // The static fields written at creation survive the done update.
        assert_eq!(
            rec.get("area").and_then(|s| s.as_str()),
            Some("macOS relay")
        );

        // The poll tool, with no in-memory entry, returns the stored report.
        let res = reader.call_live_lab_result(&json!({"job_id": job_id}));
        assert!(res.is_error.is_none(), "done record must poll non-error");
        let body = res
            .content
            .first()
            .map(|c| c.text.as_str())
            .unwrap_or_default()
            .to_string();
        assert!(body.contains("THE DONE REPORT"), "got: {body}");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn poll_surfaces_orphaned_run_outcome_from_report_dir() {
        // A labrun whose record is still "running" (the worker died on a reload)
        // but whose detached orchestrator already wrote orchestrate_result.json:
        // the poll fallback must surface the OUTCOME (overall_status + first
        // failed stage) + a "auto-triage did not run" note, not "still running".
        let root = std::env::temp_dir().join(format!(
            "deepseek_jobrec_orphan_{}_{}",
            std::process::id(),
            now_unix()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let reader = server_rooted(&root);

        let job_id = reader.new_job_id("labrun");
        let report_dir = format!("state/deepseek-lab-{job_id}");
        // Persist a "running" record (as the worker did before the reload).
        reader.write_job_record(
            &job_id,
            &json!({
                "job_id": job_id,
                "kind": "labrun",
                "state": "running",
                "area": "macOS exit",
                "report_dir": report_dir,
                "started_unix": now_unix(),
            }),
        );
        // The orphaned-but-finished orchestrator's completion artifact.
        let orch_dir = root.join(&report_dir).join("orchestration");
        std::fs::create_dir_all(&orch_dir).unwrap();
        std::fs::write(
            orch_dir.join("orchestrate_result.json"),
            json!({
                "command": "vm-lab-orchestrate-live-lab",
                "overall_status": "fail",
                "report_dir": report_dir,
                "outcomes": [
                    {"stage": "bootstrap", "status": "pass", "summary": "", "artifacts": []},
                    {"stage": "macos_exit_nat", "status": "fail", "summary": "", "artifacts": []}
                ],
                "warnings": [],
                "next_actions": []
            })
            .to_string(),
        )
        .unwrap();

        let res = reader.call_live_lab_result(&json!({"job_id": job_id}));
        assert!(res.is_error.is_none(), "orphan outcome must poll non-error");
        let body = res
            .content
            .first()
            .map(|c| c.text.as_str())
            .unwrap_or_default()
            .to_string();
        assert!(body.contains("fail"), "must surface overall_status: {body}");
        assert!(
            body.contains("macos_exit_nat"),
            "must surface first failed stage: {body}"
        );
        assert!(
            body.contains("auto-triage did NOT run") || body.contains("RELOADED"),
            "must note the reload + missing auto-triage: {body}"
        );
        assert!(
            body.contains(&report_dir),
            "must point at the report dir: {body}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    // --- job-reconcile (deepseek_reconcile_jobs) ---

    /// A pid that is guaranteed dead: spawn a short-lived child, reap it, and
    /// return its (now-defunct) pid. The OS will not reuse it within a test, so
    /// pid_is_alive(reaped) is reliably false. Spawns `true` (a no-op) so the
    /// child exits immediately.
    #[cfg(unix)]
    fn reaped_dead_pid() -> u32 {
        let mut child = std::process::Command::new("true")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn `true`");
        let pid = child.id();
        // Reap it so the pid is no longer a live (or zombie-but-signalable) target.
        let _ = child.wait();
        pid
    }

    #[test]
    #[cfg(unix)]
    fn pid_is_alive_self_is_true_reaped_is_false() {
        assert!(
            pid_is_alive(std::process::id()),
            "the current process must be alive"
        );
        assert!(
            !pid_is_alive(0),
            "pid 0 is never a live single-process target"
        );
        let dead = reaped_dead_pid();
        assert!(
            !pid_is_alive(dead),
            "a reaped child's pid {dead} must read as dead"
        );
    }

    /// (a) A running record whose report dir has a completion artifact reconciles
    /// to done, recovering the run outcome.
    #[test]
    fn reconcile_running_with_artifact_becomes_done() {
        let root = std::env::temp_dir().join(format!(
            "deepseek_reconcile_done_{}_{}",
            std::process::id(),
            now_unix()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let s = server_rooted(&root);

        let job_id = s.new_job_id("labrun");
        let report_dir = format!("state/deepseek-lab-{job_id}");
        s.write_job_record(
            &job_id,
            &json!({
                "job_id": job_id,
                "kind": "labrun",
                "state": "running",
                "area": "macOS relay",
                "report_dir": report_dir,
                "orchestrator_pid": 999_999_999u32, // irrelevant: artifact wins
                "started_unix": now_unix(),
            }),
        );
        let orch_dir = root.join(&report_dir).join("orchestration");
        std::fs::create_dir_all(&orch_dir).unwrap();
        std::fs::write(
            orch_dir.join("orchestrate_result.json"),
            json!({
                "overall_status": "pass",
                "report_dir": report_dir,
                "outcomes": [
                    {"stage": "bootstrap", "status": "pass", "summary": "", "artifacts": []}
                ],
            })
            .to_string(),
        )
        .unwrap();

        let res = s.call_reconcile_jobs(&json!({}));
        assert!(res.is_error.is_none());
        let body = res
            .content
            .first()
            .map(|c| c.text.as_str())
            .unwrap()
            .to_string();
        assert!(body.contains("reconciled 1 to **done**"), "got: {body}");

        // The record is now done and carries a recovered report_text.
        let rec = s.read_job_record(&job_id).expect("record");
        assert_eq!(rec.get("state").and_then(|v| v.as_str()), Some("done"));
        let report = rec
            .get("report_text")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert!(
            report.contains("RECONCILED to done") && report.contains("pass"),
            "recovered report must carry the outcome: {report}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// (b) A running record with a dead recorded pid and NO completion artifact
    /// reconciles to crashed.
    #[test]
    #[cfg(unix)]
    fn reconcile_running_with_dead_pid_no_artifact_becomes_crashed() {
        let root = std::env::temp_dir().join(format!(
            "deepseek_reconcile_crash_{}_{}",
            std::process::id(),
            now_unix()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let s = server_rooted(&root);

        let dead = reaped_dead_pid();
        let job_id = s.new_job_id("labrun");
        let report_dir = format!("state/deepseek-lab-{job_id}");
        s.write_job_record(
            &job_id,
            &json!({
                "job_id": job_id,
                "kind": "labrun",
                "state": "running",
                "area": "macOS exit",
                "report_dir": report_dir, // dir/artifact intentionally absent
                "orchestrator_pid": dead,
                "started_unix": now_unix(),
            }),
        );

        let res = s.call_reconcile_jobs(&json!({"job_id": job_id}));
        assert!(res.is_error.is_none());
        let body = res
            .content
            .first()
            .map(|c| c.text.as_str())
            .unwrap()
            .to_string();
        assert!(body.contains("reconciled"), "got: {body}");
        assert!(
            body.contains("crashed"),
            "must report a crashed record: {body}"
        );

        let rec = s.read_job_record(&job_id).expect("record");
        assert_eq!(rec.get("state").and_then(|v| v.as_str()), Some("crashed"));
        let note = rec
            .get("reconcile_note")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert!(
            note.contains("is dead and no completion artifact"),
            "crashed record must carry the reconcile note: {note}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// (c) A record with no pid recorded and no artifact stays running
    /// (conservative — could be a pre-pid-spawn record genuinely in flight).
    #[test]
    fn reconcile_running_no_pid_no_artifact_stays_running() {
        let root = std::env::temp_dir().join(format!(
            "deepseek_reconcile_stay_{}_{}",
            std::process::id(),
            now_unix()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let s = server_rooted(&root);

        let job_id = s.new_job_id("labrun");
        let report_dir = format!("state/deepseek-lab-{job_id}");
        s.write_job_record(
            &job_id,
            &json!({
                "job_id": job_id,
                "kind": "labrun",
                "state": "running",
                "area": "Windows admin",
                "report_dir": report_dir, // no artifact, no orchestrator_pid
                "started_unix": now_unix(),
            }),
        );

        let res = s.call_reconcile_jobs(&json!({}));
        assert!(res.is_error.is_none());
        let body = res
            .content
            .first()
            .map(|c| c.text.as_str())
            .unwrap()
            .to_string();
        assert!(body.contains("left 1 **running**"), "got: {body}");

        // Old records without orchestrator_pid still parse (backward-compatible).
        let rec = s.read_job_record(&job_id).expect("record");
        assert_eq!(rec.get("state").and_then(|v| v.as_str()), Some("running"));
        assert!(DeepSeekServer::job_orchestrator_pid(&rec).is_none());

        let _ = std::fs::remove_dir_all(&root);
    }

    /// (d) The in-flight filter does NOT count a dead-pid/no-artifact record, so a
    /// crashed run no longer blocks the next deepseek_lab_run — even before anyone
    /// calls deepseek_reconcile_jobs. A no-pid/no-artifact record IS still counted.
    #[test]
    #[cfg(unix)]
    fn in_flight_filter_self_heals_on_dead_pid() {
        let root = std::env::temp_dir().join(format!(
            "deepseek_inflight_selfheal_{}_{}",
            std::process::id(),
            now_unix()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let s = server_rooted(&root);

        // A crashed run: state=running, dead pid, no completion artifact.
        let dead = reaped_dead_pid();
        let crashed = s.new_job_id("labrun");
        s.write_job_record(
            &crashed,
            &json!({
                "job_id": crashed,
                "kind": "labrun",
                "state": "running",
                "area": "x",
                "report_dir": format!("state/deepseek-lab-{crashed}"),
                "orchestrator_pid": dead,
                "started_unix": now_unix(),
            }),
        );
        assert_eq!(
            s.running_lab_jobs(),
            0,
            "a dead-pid/no-artifact record must NOT count as in flight"
        );

        // A genuinely-indeterminate run: state=running, NO pid, no artifact → still
        // counted (conservative).
        let indeterminate = s.new_job_id("labrun");
        s.write_job_record(
            &indeterminate,
            &json!({
                "job_id": indeterminate,
                "kind": "labrun",
                "state": "running",
                "area": "y",
                "report_dir": format!("state/deepseek-lab-{indeterminate}"),
                "started_unix": now_unix(),
            }),
        );
        assert_eq!(
            s.running_lab_jobs(),
            1,
            "a no-pid/no-artifact record stays counted; only the dead-pid one self-heals"
        );

        // An AGED no-pid/no-artifact record (older than the startup window) is a
        // phantom — the worker died before recording a pid — and must NOT count,
        // so the gate self-heals without an explicit reconcile call. The running
        // total stays 1 (the young indeterminate one above).
        let aged_phantom = s.new_job_id("labrun");
        s.write_job_record(
            &aged_phantom,
            &json!({
                "job_id": aged_phantom,
                "kind": "labrun",
                "state": "running",
                "area": "z",
                "report_dir": format!("state/deepseek-lab-{aged_phantom}"),
                "started_unix": now_unix().saturating_sub(RECONCILE_NO_PID_STALE_SECS + 60),
            }),
        );
        assert_eq!(
            s.running_lab_jobs(),
            1,
            "an aged no-pid/no-artifact phantom must NOT count as in flight"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// (e) A no-pid/no-artifact record OLDER than the startup window is a phantom
    /// (worker died before spawning the orchestrator) and reconcile reclassifies it
    /// crashed, so it stops pegging the singleton gate permanently.
    #[test]
    fn reconcile_running_no_pid_no_artifact_aged_becomes_crashed() {
        let root = std::env::temp_dir().join(format!(
            "deepseek_reconcile_aged_{}_{}",
            std::process::id(),
            now_unix()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let s = server_rooted(&root);

        let job_id = s.new_job_id("labrun");
        let report_dir = format!("state/deepseek-lab-{job_id}");
        s.write_job_record(
            &job_id,
            &json!({
                "job_id": job_id,
                "kind": "labrun",
                "state": "running",
                "area": "macOS anchor",
                "report_dir": report_dir, // no artifact, no orchestrator_pid
                "started_unix": now_unix().saturating_sub(RECONCILE_NO_PID_STALE_SECS + 120),
            }),
        );

        let res = s.call_reconcile_jobs(&json!({"job_id": job_id}));
        assert!(res.is_error.is_none());
        let body = res
            .content
            .first()
            .map(|c| c.text.as_str())
            .unwrap()
            .to_string();
        assert!(body.contains("crashed"), "must report crashed: {body}");

        let rec = s.read_job_record(&job_id).expect("record");
        assert_eq!(rec.get("state").and_then(|v| v.as_str()), Some("crashed"));
        let note = rec
            .get("reconcile_note")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert!(
            note.contains("no orchestrator pid was ever recorded"),
            "aged phantom must carry the reconcile note: {note}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
