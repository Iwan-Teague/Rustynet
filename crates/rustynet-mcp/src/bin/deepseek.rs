//! DeepSeek MCP Server — calls the DeepSeek API as a first-class sub-agent tool.
//!
//! Four tools with explicit intent levels so the calling agent can choose the
//! right level of access:
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
    McpServer, ServerInfo, Tool, ToolCallResult, json_schema_object, json_schema_string, repo_root,
    run_server, run_with_timeout, text_content, tool_error, truncate_output,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
/// Standard lab SSH material + inventory (mirrors the lab-state MCP defaults).
const LAB_SSH_IDENTITY_REL: &str = ".ssh/rustynet_lab_ed25519";
const LAB_KNOWN_HOSTS_REL: &str = ".ssh/known_hosts";

/// State of an async triage job: still running (with its start time, for elapsed
/// reporting) or finished with its assembled report.
enum TriageJob {
    Running { started: Instant },
    Done(String),
}

type JobMap = Arc<Mutex<HashMap<String, TriageJob>>>;

#[derive(Clone)]
struct DeepSeekServer {
    api_key: String,
    agent: ureq::Agent,
    repo_root: PathBuf,
    /// Async triage jobs keyed by job id. Shared (Arc) so a clone handed to a
    /// worker thread mutates the same map the poll tool reads.
    jobs: JobMap,
    /// Monotonic counter for unique triage job ids within a server lifetime.
    job_counter: Arc<AtomicU64>,
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
            job_counter: Arc::new(AtomicU64::new(1)),
        }
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
        self.run_grounded("agent", AGENT_SYSTEM_PROMPT, prompt, model, max_steps)
    }

    /// The grounded read-only tool-calling loop, parameterized by system prompt
    /// so the failure-triage roles (research / verify / review) reuse the exact
    /// same confined, read-only tool set + loop, swapping only the instructions.
    /// No role can write — the tool set is read-only for every system prompt.
    fn run_grounded(
        &self,
        label: &str,
        system: &str,
        prompt: &str,
        model: &str,
        max_steps: u64,
    ) -> Result<String, String> {
        let tools = agent_tool_definitions();
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
             lab_guest_exec, utm_vm_status, lab_node_reachable). Ground EVERY claim in a file:line or \
             log line you actually opened — never infer from memory — and cross-check with a second \
             tool (grep → read_file, or find_definition → find_references, or git blame on the line) \
             before asserting it."
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

                        let result = self.dispatch_agent_tool(name, &args);
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
        let job_id = format!(
            "triage-{}",
            self.job_counter.fetch_add(1, Ordering::Relaxed)
        );
        if let Ok(mut jobs) = self.jobs.lock() {
            jobs.insert(
                job_id.clone(),
                TriageJob::Running {
                    started: Instant::now(),
                },
            );
        }

        let worker = self.clone();
        let jid = job_id.clone();
        let target_label = target.clone();
        let ctx = format!("Target under test: {target}\n\n{failure_context}");
        std::thread::spawn(move || {
            let report = worker.run_triage(&ctx, max_steps);
            let body = format!(
                "[deepseek live-lab triage | target={target_label} | budget={max_steps}/step]\n\n{report}"
            );
            if let Ok(mut jobs) = worker.jobs.lock() {
                jobs.insert(jid, TriageJob::Done(body));
            }
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
        let jobs = match self.jobs.lock() {
            Ok(j) => j,
            Err(_) => return tool_error("triage job store is poisoned"),
        };
        match jobs.get(job_id) {
            Some(TriageJob::Done(report)) => ToolCallResult {
                content: text_content(report.clone()),
                is_error: None,
            },
            Some(TriageJob::Running { started }) => ToolCallResult {
                content: text_content(format!(
                    "Triage job `{job_id}` still running ({}s elapsed). Poll again in ~30-60s.",
                    started.elapsed().as_secs()
                )),
                is_error: None,
            },
            None => tool_error(&format!(
                "unknown job_id '{job_id}' — not found (it may have been lost on an MCP-server \
                 reload; re-run deepseek_live_lab)"
            )),
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
            if p == platform {
                if let Some(a) = e.get("alias").and_then(|v| v.as_str()) {
                    return Some(a.to_string());
                }
            }
        }
        None
    }

    /// Count in-flight lab-run jobs — the lab is a singleton, never two
    /// orchestrations on the VMs at once.
    fn running_lab_jobs(&self) -> usize {
        self.jobs
            .lock()
            .map(|jobs| {
                jobs.iter()
                    .filter(|(id, j)| {
                        id.starts_with("labrun-") && matches!(j, TriageJob::Running { .. })
                    })
                    .count()
            })
            .unwrap_or(0)
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

        let job_id = format!(
            "labrun-{}",
            self.job_counter.fetch_add(1, Ordering::Relaxed)
        );
        if let Ok(mut jobs) = self.jobs.lock() {
            jobs.insert(
                job_id.clone(),
                TriageJob::Running {
                    started: Instant::now(),
                },
            );
        }

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
        let report_dir = format!("state/deepseek-lab-{job_id}");
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
                dry_run,
            ));
            let arg_refs: Vec<&str> = cargo_args.iter().map(String::as_str).collect();

            let body = match run_with_timeout(
                "cargo",
                &arg_refs,
                &worker.repo_root,
                &env,
                Duration::from_secs(LAB_ORCHESTRATOR_TIMEOUT_SECS),
            ) {
                Ok(o) if o.success => format!(
                    "# Live-lab run: {area} — PASS\n\nThe orchestration completed successfully. \
                     Evidence in `{report_dir}` (verify the matrix row + per-stage results before \
                     trusting). No triage needed.\n\n_stdout tail:_\n{}",
                    truncate_output(&o.stdout, 60, 4000)
                ),
                Ok(o) if dry_run => format!(
                    "# Live-lab run: {area} — DRY-RUN wiring check complete\n\nThe orchestrator's \
                     non-zero exit is EXPECTED in --dry-run (every stage is skipped, so the \
                     setup-complete check can't pass). The launch → wait → capture → report path is \
                     verified; no triage is run for a dry run.\n\n_output tail:_\n{}",
                    truncate_output(&o.stdout, 60, 4000)
                ),
                Ok(o) => {
                    // Real run FAILED → feed the evidence to the rigid triage pipeline.
                    let failure_context = format!(
                        "Live-lab orchestration for area '{area}' FAILED (orchestrator exited \
                         non-zero). Report dir the grounded agents can read: {report_dir}. \
                         Orchestrator output tail:\n{}\n{}",
                        truncate_output(&o.stdout, 80, 6000),
                        truncate_output(&o.stderr, 40, 3000)
                    );
                    let triage = worker.run_triage(&failure_context, max_steps);
                    format!(
                        "# Live-lab run: {area} — FAIL → triage\n\nReport dir: `{report_dir}`\n\n{triage}"
                    )
                }
                Err(e) => format!(
                    "# Live-lab run: {area} — could not launch the orchestrator: {e}\n\n(Is `cargo` \
                     on PATH, the inventory ready, and SSH material present? This is an \
                     infrastructure error, not a lab failure.)"
                ),
            };
            if let Ok(mut jobs) = worker.jobs.lock() {
                jobs.insert(jid, TriageJob::Done(body));
            }
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
        records.sort_by(|a, b| b.0.cmp(&a.0));
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
        // The enum maps to a HARD-CODED command — never caller-supplied argv.
        let cmd: &[&str] = match check {
            "network" => &["/usr/sbin/ip", "-br", "addr"],
            "routes" => &["/usr/sbin/ip", "route"],
            "dns" => &["/bin/cat", "/etc/resolv.conf"],
            "daemon" => &["/usr/bin/systemctl", "is-active", "rustynetd"],
            other => {
                return Err(format!(
                    "invalid check '{other}': must be one of network|routes|dns|daemon"
                ));
            }
        };

        // Resolve alias → (utm_name, platform) from the inventory.
        let (utm_name, platform) = self
            .lab_inventory_alias(vm_alias)?
            .ok_or_else(|| format!("unknown vm_alias '{vm_alias}' (not in inventory)"))?;
        // Linux-only: macOS UTM uses Apple Virtualization (no utmctl exec);
        // Windows guests do not run these Linux commands. Fail closed.
        if platform != "linux" {
            return Err(format!(
                "vm_alias '{vm_alias}' is platform '{platform}'; lab_guest_exec only targets Linux guests (utmctl exec)"
            ));
        }

        let utmctl = utmctl_path();
        // Require the guest to be running — utmctl exec only answers a started VM.
        let power = self.utm_power_status(&utmctl, &utm_name)?;
        if power.as_deref() != Some("started") {
            return Err(format!(
                "VM '{vm_alias}' (utm_name={utm_name}) is '{}', not started — cannot exec into a non-running guest",
                power.as_deref().unwrap_or("unknown")
            ));
        }

        // argv-only utmctl exec: utm_name + the fixed command, no shell.
        let mut argv: Vec<&str> = vec!["exec", &utm_name, "--cmd"];
        argv.extend_from_slice(cmd);
        let outcome = run_with_timeout(
            &utmctl,
            &argv,
            &self.repo_root,
            &[],
            Duration::from_secs(SUBPROC_TIMEOUT_SECS),
        )?;
        let mut out = format!(
            "# lab_guest_exec {vm_alias} [{check}] (utm_name={utm_name})\n\n`{}`\n\n",
            cmd.join(" ")
        );
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

    /// Resolve an inventory alias → (utm_name, platform). Mirrors lab_state's
    /// inventory parse: Linux entries have no `platform` field → "linux". Returns
    /// Ok(None) when the alias is absent. The inventory path is confined.
    fn lab_inventory_alias(&self, alias: &str) -> Result<Option<(String, String)>, String> {
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
            // utm_name is required to exec — its absence means no controller.
            let Some(utm_name) = e
                .get("controller")
                .and_then(|c| c.get("utm_name"))
                .and_then(|v| v.as_str())
            else {
                return Err(format!(
                    "alias '{alias}' has no controller.utm_name (not a local UTM guest)"
                ));
            };
            let platform = e
                .get("platform")
                .and_then(|v| v.as_str())
                .filter(|p| !p.is_empty())
                .unwrap_or("linux")
                .to_string();
            return Ok(Some((utm_name.to_string(), platform)));
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
    dry_run: bool,
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
    if dry_run {
        a.push("--dry-run".to_string());
    }
    a
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
- lab_guest_exec — run ONE fixed read-only command inside a running LINUX guest via \
  utmctl exec: check=network|routes|dns|daemon ONLY (ip -br addr / ip route / \
  cat /etc/resolv.conf / systemctl is-active rustynetd). The command is fixed, not \
  caller-controlled; it cannot write or run arbitrary commands. USE THIS for live \
  Linux-guest network/DNS/daemon state. \
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
            "Run ONE fixed read-only diagnostic command inside a named, running LINUX UTM guest via \
             utmctl exec. The command is selected by `check` (network=`ip -br addr`, routes=`ip route`, \
             dns=`cat /etc/resolv.conf`, daemon=`systemctl is-active rustynetd`) and is NOT \
             caller-controlled — there is no arbitrary exec, no writes. Fails closed if the guest is \
             absent, not running, or not Linux.",
            json!({
                "vm_alias": {"type": "string", "description": "Inventory alias of a Linux guest, e.g. 'debian-headless-1'"},
                "check": {"type": "string", "enum": ["network", "routes", "dns", "daemon"], "description": "Which fixed read-only command to run"}
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
    ])
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
                    Linux-guest commands], host_system_info, host_disk_status, lab_run_status, \
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
                        "allow_concurrent": json!({"type": "boolean", "description": "Opt into PARALLEL runs (default false = singleton). When true, up to 3 runs may overlap — you MUST give each disjoint guests (e.g. the macOS↔Windows pipeline: macOS on one Debian backbone, Windows on another). Each concurrent run gets its own CARGO_TARGET_DIR + report dir."}),
                        "dry_run": json!({"type": "boolean", "description": "Run the orchestrator in --dry-run mode (fast; verifies the launch wiring without a real lab pass)."}),
                        "max_steps": json!({"type": "integer", "description": "Max tool-calling steps per triage agent on failure (default 12, cap 20)."}),
                    }),
                    vec!["area"],
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
        assert_eq!(arr.len(), 21);
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
        ] {
            assert!(
                !names.contains(&forbidden),
                "proxy/top-level tool {forbidden} must NOT be in the agent tool-set"
            );
        }
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
            false,
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
        assert!(!a.iter().any(|x| x == "--windows-vm"));
        assert!(!a.iter().any(|x| x == "--client-vm"));
        assert!(!a.iter().any(|x| x == "--dry-run"));
        // dry_run adds the flag; no macOS/Windows/backbone/rebuild when omitted.
        let d = build_orchestrator_args("inv", "s", "k", "r", None, None, None, None, None, true);
        assert!(d.iter().any(|x| x == "--dry-run"));
        assert!(!d.iter().any(|x| x == "--macos-vm"));
        assert!(!d.iter().any(|x| x == "--exit-vm"));
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
}
