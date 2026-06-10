//! Shared MCP (Model Context Protocol) library for Rustynet agent tools.
//!
//! Implements JSON-RPC 2.0 over stdio per the MCP specification.
//! Each binary server registers tools and runs the main loop via `run_server`.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

// ── Repo root resolution ─────────────────────────────────────────────

/// Resolve the Rustynet repository root directory.
/// Checks RUSTYNET_REPO_ROOT env, then the compile-time baked path, then PWD,
/// finally falls back to the current dir.
pub fn repo_root() -> PathBuf {
    // First check explicit env override (for testing)
    if let Ok(dir) = std::env::var("RUSTYNET_REPO_ROOT") {
        let p = PathBuf::from(&dir);
        if p.is_dir() {
            return p;
        }
    }
    // Use the compile-time baked path (set via build.rs). This must be
    // option_env! — a runtime env::var never sees cargo:rustc-env values, which
    // left servers rooted at the client's CWD when launched outside the repo.
    if let Some(dir) = option_env!("RUSTYNET_REPO_BAKED") {
        let p = PathBuf::from(dir);
        if p.is_dir() {
            return p;
        }
    }
    // Fallback: try PWD
    if let Ok(dir) = std::env::var("PWD") {
        let p = PathBuf::from(&dir);
        if p.is_dir() {
            return p;
        }
    }
    PathBuf::from(".")
}

/// Full version string with build provenance (git short SHA + a `-dirty` flag +
/// build time), baked by `build.rs`. Each server reports this as
/// `serverInfo.version` during `initialize`, so stale-binary drift — a client
/// launched an old `./bin` while the tree moved on — is detectable by comparing
/// it against the working tree's `git rev-parse HEAD`.
pub fn server_version() -> String {
    let pkg = env!("CARGO_PKG_VERSION");
    let sha = option_env!("RUSTYNET_GIT_SHA").unwrap_or("unknown");
    let built = option_env!("RUSTYNET_BUILD_TIME").unwrap_or("unknown");
    format!("{pkg} (git {sha}, built {built})")
}

// ── JSON-RPC 2.0 types ────────────────────────────────────────────────

pub const JSONRPC_VERSION: &str = "2.0";

/// The MCP protocol version this server prefers to speak (newest we support;
/// used as the fallback when a client requests an unknown version).
pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// MCP protocol revisions this server is compatible with. During `initialize`
/// the server echoes the client's requested version if it is in this set;
/// otherwise it responds with [`PROTOCOL_VERSION`].
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct EmptyResult {}

// ── MCP types ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Tool {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

#[derive(Debug, Deserialize)]
pub struct ToolCallParams {
    pub name: String,
    #[serde(default)]
    pub arguments: Option<Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolCallResult {
    pub content: Vec<ContentItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct ContentItem {
    #[serde(rename = "type")]
    pub content_type: String,
    pub text: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerCapabilities {
    pub tools: ToolsCapability,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourcesCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompts: Option<PromptsCapability>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolsCapability {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list_changed: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourcesCapability {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list_changed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscribe: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptsCapability {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list_changed: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeResult {
    pub protocol_version: String,
    pub capabilities: ServerCapabilities,
    pub server_info: ServerInfo,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Serialize)]
pub struct ListToolsResult {
    pub tools: Vec<Tool>,
}

#[derive(Debug, Serialize)]
pub struct ListResourcesResult {
    pub resources: Vec<Resource>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Resource {
    pub uri: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ReadResourceResult {
    pub contents: Vec<ResourceContent>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceContent {
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

// ── MCP prompt types ──────────────────────────────────────────────────

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Prompt {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<PromptArgument>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PromptArgument {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetPromptResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub messages: Vec<PromptMessage>,
}

#[derive(Debug, Serialize)]
pub struct PromptMessage {
    pub role: String,
    pub content: ContentItem,
}

/// Build a single-message prompt result with a user-role text message.
pub fn prompt_text(description: &str, text: String) -> GetPromptResult {
    GetPromptResult {
        description: Some(description.to_string()),
        messages: vec![PromptMessage {
            role: "user".into(),
            content: ContentItem {
                content_type: "text".into(),
                text,
            },
        }],
    }
}

// ── Error codes ───────────────────────────────────────────────────────

pub const PARSE_ERROR: i32 = -32700;
pub const INVALID_REQUEST: i32 = -32600;
pub const METHOD_NOT_FOUND: i32 = -32601;
pub const INVALID_PARAMS: i32 = -32602;
pub const INTERNAL_ERROR: i32 = -32603;

// ── Response helpers ──────────────────────────────────────────────────

pub fn make_response(id: Option<Value>, result: Value) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: JSONRPC_VERSION.into(),
        id,
        result: Some(result),
        error: None,
    }
}

pub fn make_error(id: Option<Value>, code: i32, message: &str) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: JSONRPC_VERSION.into(),
        id,
        result: None,
        error: Some(JsonRpcError {
            code,
            message: message.into(),
            data: None,
        }),
    }
}

pub fn text_content(text: String) -> Vec<ContentItem> {
    vec![ContentItem {
        content_type: "text".into(),
        text,
    }]
}

pub fn tool_error(msg: &str) -> ToolCallResult {
    ToolCallResult {
        content: text_content(msg.to_string()),
        is_error: Some(true),
    }
}

pub fn tool_success(msg: &str) -> ToolCallResult {
    ToolCallResult {
        content: text_content(msg.to_string()),
        is_error: None,
    }
}

// ── JSON Schema helpers ──────────────────────────────────────────────

pub fn json_schema_object(properties: serde_json::Value, required: Vec<&str>) -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": properties,
        "required": required,
    })
}

pub fn json_schema_string(description: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "string",
        "description": description,
    })
}

pub fn json_schema_boolean(description: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "boolean",
        "description": description,
    })
}

pub fn json_schema_array_string(description: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "array",
        "items": {"type": "string"},
        "description": description,
    })
}

// ── Output truncation ─────────────────────────────────────────────────

/// Truncate text to at most `max_lines` lines and `max_bytes` bytes (whichever
/// is hit first), appending a note. Guards against both pathologically long
/// single lines and huge multi-line dumps blowing up an MCP response.
pub fn truncate_output(text: &str, max_lines: usize, max_bytes: usize) -> String {
    let total_lines = text.lines().count();
    let mut out = if total_lines > max_lines {
        let head: String = text.lines().take(max_lines).collect::<Vec<_>>().join("\n");
        format!("{head}\n... (truncated: showing {max_lines} of {total_lines} lines)")
    } else {
        text.to_string()
    };
    if out.len() > max_bytes {
        // Truncate on a UTF-8 char boundary at or below max_bytes.
        let mut end = max_bytes;
        while end > 0 && !out.is_char_boundary(end) {
            end -= 1;
        }
        out.truncate(end);
        out.push_str("\n... (truncated: output exceeded byte limit)");
    }
    out
}

/// Like [`truncate_output`] but keeps the END of the text. This is the right
/// choice for cargo/test output: the verdict an agent needs (`error[...]`,
/// `test result: FAILED`, panics, `failures:`) lands at the TAIL, while the head
/// is just "Compiling ..." preamble. Head-truncating those would hide the bug.
pub fn truncate_tail(text: &str, max_lines: usize, max_bytes: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let total = lines.len();
    let mut out = if total > max_lines {
        let tail = lines[total - max_lines..].join("\n");
        format!("... (truncated: showing last {max_lines} of {total} lines)\n{tail}")
    } else {
        text.to_string()
    };
    if out.len() > max_bytes {
        // Keep the tail: drop from the front, on a UTF-8 char boundary.
        let mut start = out.len() - max_bytes;
        while start < out.len() && !out.is_char_boundary(start) {
            start += 1;
        }
        out = format!(
            "... (truncated: output exceeded byte limit)\n{}",
            &out[start..]
        );
    }
    out
}

// ── Bounded external command execution ───────────────────────────────

/// Outcome of running an external command with a timeout watchdog.
pub struct CommandOutcome {
    /// Process exit code, or `None` if the process was killed / produced no code.
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    /// True if the command was killed because it exceeded the timeout.
    pub timed_out: bool,
    /// True if the process exited 0 (and was not killed).
    pub success: bool,
}

/// Run `program` with `args` in `cwd`, capturing stdout/stderr, with a hard
/// timeout. On timeout the child is **killed** (and reaped) so it cannot leak
/// and hold build locks — killing the cargo parent releases the `target/` lock.
///
/// `extra_env` is applied to the child environment.
pub fn run_with_timeout(
    program: &str,
    args: &[&str],
    cwd: &Path,
    extra_env: &[(&str, &str)],
    timeout: Duration,
) -> Result<CommandOutcome, String> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("Failed to spawn '{program}': {e}"))?;

    // Drain stdout/stderr on dedicated threads so a full pipe buffer can never
    // deadlock the child before we get a chance to time it out.
    let mut out_pipe = child
        .stdout
        .take()
        .ok_or_else(|| "child stdout unavailable".to_string())?;
    let mut err_pipe = child
        .stderr
        .take()
        .ok_or_else(|| "child stderr unavailable".to_string())?;
    let out_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = out_pipe.read_to_end(&mut buf);
        buf
    });
    let err_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = err_pipe.read_to_end(&mut buf);
        buf
    });

    let start = Instant::now();
    let mut timed_out = false;
    // `ExitStatus` is `Copy`, so we can inspect it twice below.
    let status: Option<std::process::ExitStatus> = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    timed_out = true;
                    // Reap the killed child (releases the cargo build lock).
                    break child.wait().ok();
                }
                std::thread::sleep(Duration::from_millis(80));
            }
            Err(e) => return Err(format!("error waiting on '{program}': {e}")),
        }
    };

    let stdout = String::from_utf8_lossy(&out_handle.join().unwrap_or_default()).to_string();
    let stderr = String::from_utf8_lossy(&err_handle.join().unwrap_or_default()).to_string();

    Ok(CommandOutcome {
        code: status.and_then(|s| s.code()),
        stdout,
        stderr,
        timed_out,
        success: !timed_out && status.map(|s| s.success()).unwrap_or(false),
    })
}

/// Format a [`CommandOutcome`] into a Markdown report (header, exit code,
/// pass/fail/timeout banner, truncated stdout/stderr) and a `ToolCallResult`
/// whose `is_error` flag reflects failure or timeout.
pub fn outcome_to_result(title: &str, outcome: &CommandOutcome) -> ToolCallResult {
    let mut result = format!("# {title}\n\n");
    if outcome.timed_out {
        result.push_str("## ⏱️ TIMED OUT (process killed)\n\n");
    } else if outcome.success {
        result.push_str("## ✅ PASSED\n\n");
    } else {
        result.push_str("## ❌ FAILED\n\n");
    }
    result.push_str(&format!(
        "**Exit code:** {}\n\n",
        outcome
            .code
            .map(|c| c.to_string())
            .unwrap_or_else(|| "killed".into())
    ));

    // Tail-bias: cargo/test put the verdict + errors at the END.
    let stdout = outcome.stdout.trim();
    if !stdout.is_empty() {
        result.push_str(&format!(
            "### stdout\n```\n{}\n```\n\n",
            truncate_tail(stdout, 200, 60_000)
        ));
    }
    let stderr = outcome.stderr.trim();
    if !stderr.is_empty() {
        result.push_str(&format!(
            "### stderr\n```\n{}\n```\n\n",
            truncate_tail(stderr, 120, 40_000)
        ));
    }

    ToolCallResult {
        content: text_content(result),
        is_error: if outcome.success { None } else { Some(true) },
    }
}

// ── Detached background jobs ──────────────────────────────────────────

/// Spawn `program` with `args` in `cwd`, redirecting stdout+stderr to a freshly
/// created `log_path`, with `extra_env`. Does NOT wait — returns the running
/// child so the caller can poll/kill it. The child keeps running even if this
/// process later exits (it is reparented to init), which is what lets a
/// multi-hour lab run outlive an MCP-server reload. argv-only: no shell, so
/// arguments can never be interpreted as shell metacharacters.
pub fn spawn_logged(
    program: &str,
    args: &[&str],
    cwd: &Path,
    extra_env: &[(&str, &str)],
    log_path: &Path,
) -> Result<std::process::Child, String> {
    let log = std::fs::File::create(log_path)
        .map_err(|e| format!("cannot create log {}: {e}", log_path.display()))?;
    let log_err = log
        .try_clone()
        .map_err(|e| format!("cannot clone log handle: {e}"))?;
    let mut cmd = Command::new(program);
    cmd.args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err));
    // Make the job its own process-group leader so cancellation can signal the
    // WHOLE tree (orchestrator → bash workers → utmctl pushes). Killing only
    // the leader leaves workers orphaned and still mutating the lab.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.spawn()
        .map_err(|e| format!("failed to spawn '{program}': {e}"))
}

/// Return the last `lines` lines of a UTF-8 (lossy) file, reading at most the
/// final 256 KiB so a multi-GB log (a 24h run) can never blow up memory.
pub fn tail_file(path: &Path, lines: usize) -> Result<String, String> {
    const MAX_TAIL_BYTES: u64 = 256 * 1024;
    let mut f =
        std::fs::File::open(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let start = len.saturating_sub(MAX_TAIL_BYTES);
    if start > 0 {
        f.seek(SeekFrom::Start(start))
            .map_err(|e| format!("seek failed: {e}"))?;
    }
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)
        .map_err(|e| format!("read failed: {e}"))?;
    let text = String::from_utf8_lossy(&buf);
    // If we started mid-file, drop the leading partial line.
    let text: &str = if start > 0 {
        match text.find('\n') {
            Some(i) => &text[i + 1..],
            None => &text,
        }
    } else {
        &text
    };
    let all: Vec<&str> = text.lines().collect();
    let from = all.len().saturating_sub(lines);
    Ok(all[from..].join("\n"))
}

/// Read at most `max_bytes` of a file as UTF-8 (lossy), appending a note if the
/// file was longer. Bounds memory for arbitrarily large run artifacts.
pub fn read_file_capped(path: &Path, max_bytes: usize) -> Result<String, String> {
    let f =
        std::fs::File::open(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let mut buf = Vec::new();
    f.take(max_bytes as u64)
        .read_to_end(&mut buf)
        .map_err(|e| format!("read failed: {e}"))?;
    let mut out = String::from_utf8_lossy(&buf).to_string();
    if len as usize > max_bytes {
        out.push_str(&format!(
            "\n... (truncated: read {max_bytes} of {len} bytes; use tail_job_log or a narrower path)"
        ));
    }
    Ok(out)
}

// ── Server trait ──────────────────────────────────────────────────────

/// Implement this trait to create an MCP server.
///
/// `resources`/`read_resource` and `prompts`/`get_prompt` are optional; the
/// default impls expose nothing and the corresponding capability is not
/// advertised.
pub trait McpServer {
    /// Server metadata returned during initialization.
    fn server_info(&self) -> ServerInfo;

    /// The list of tools this server exposes.
    fn tools(&self) -> Vec<Tool>;

    /// Handle a tool call. `arguments` is the raw JSON params.
    fn call_tool(&self, name: &str, arguments: Option<Value>) -> ToolCallResult;

    /// Resources this server exposes (default: none).
    fn resources(&self) -> Vec<Resource> {
        Vec::new()
    }

    /// Read a resource by URI (default: none).
    fn read_resource(&self, _uri: &str) -> Option<ReadResourceResult> {
        None
    }

    /// Prompts this server exposes (default: none).
    fn prompts(&self) -> Vec<Prompt> {
        Vec::new()
    }

    /// Render a prompt by name with arguments (default: none).
    fn get_prompt(&self, _name: &str, _arguments: Option<Value>) -> Option<GetPromptResult> {
        None
    }
}

/// Run the MCP server main loop. Reads JSON-RPC requests from stdin,
/// dispatches to the server impl, writes responses to stdout.
pub fn run_server(server: impl McpServer) {
    eprintln!(
        "[rustynet-mcp] starting {} v{}",
        server.server_info().name,
        server.server_info().version
    );
    let stdin = std::io::stdin();
    let reader = BufReader::new(stdin.lock());
    let mut stdout = std::io::stdout();

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                let resp = make_error(None, PARSE_ERROR, &format!("I/O error: {e}"));
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string(&resp).unwrap_or_default()
                );
                let _ = stdout.flush();
                continue;
            }
        };

        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let req: JsonRpcRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = make_error(None, PARSE_ERROR, &format!("Parse error: {e}"));
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string(&resp).unwrap_or_default()
                );
                let _ = stdout.flush();
                continue;
            }
        };

        let response = handle_request(&server, &req);
        if let Some(resp) = response {
            let _ = writeln!(
                stdout,
                "{}",
                serde_json::to_string(&resp).unwrap_or_default()
            );
            let _ = stdout.flush();
        }
    }
}

/// Negotiate the protocol version: echo the client's requested version if we
/// support it, otherwise respond with our preferred [`PROTOCOL_VERSION`].
fn negotiate_protocol_version(requested: Option<&str>) -> String {
    match requested {
        Some(v) if SUPPORTED_PROTOCOL_VERSIONS.contains(&v) => v.to_string(),
        _ => PROTOCOL_VERSION.to_string(),
    }
}

/// Extract a human-readable message from a caught panic payload (the `Box<dyn
/// Any>` returned by `catch_unwind`). Panics carry either a `&str` or a `String`.
fn panic_message(panic: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = panic.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = panic.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic payload".to_string()
    }
}

fn handle_request(server: &impl McpServer, req: &JsonRpcRequest) -> Option<JsonRpcResponse> {
    eprintln!("[rustynet-mcp] <- {} id={:?}", req.method, req.id);

    // JSON-RPC notifications (no `id`) must never receive a response. A real
    // client always sends `initialize` with an id; a no-id initialize is
    // malformed and is correctly ignored here (avoids emitting an id-less
    // response, which would itself violate JSON-RPC).
    req.id.as_ref()?;

    match req.method.as_str() {
        "initialize" => {
            let requested = req
                .params
                .as_ref()
                .and_then(|p| p.get("protocolVersion"))
                .and_then(|v| v.as_str());

            let has_resources = !server.resources().is_empty();
            let has_prompts = !server.prompts().is_empty();

            let result = serde_json::to_value(InitializeResult {
                protocol_version: negotiate_protocol_version(requested),
                capabilities: ServerCapabilities {
                    tools: ToolsCapability {
                        list_changed: Some(false),
                    },
                    resources: has_resources.then_some(ResourcesCapability {
                        list_changed: Some(false),
                        subscribe: Some(false),
                    }),
                    prompts: has_prompts.then_some(PromptsCapability {
                        list_changed: Some(false),
                    }),
                },
                server_info: server.server_info(),
            })
            .unwrap_or(Value::Null);
            Some(make_response(req.id.clone(), result))
        }

        "tools/list" => {
            let result = serde_json::to_value(ListToolsResult {
                tools: server.tools(),
            })
            .unwrap_or(Value::Null);
            Some(make_response(req.id.clone(), result))
        }

        "tools/call" => {
            let params: ToolCallParams = match req.params.clone().map(serde_json::from_value) {
                Some(Ok(p)) => p,
                Some(Err(e)) => {
                    return Some(make_error(
                        req.id.clone(),
                        INVALID_PARAMS,
                        &format!("Invalid tool call params: {e}"),
                    ));
                }
                None => {
                    return Some(make_error(
                        req.id.clone(),
                        INVALID_PARAMS,
                        "Missing tool call params",
                    ));
                }
            };

            // Isolate tool panics. This loop is single-threaded with no outer
            // guard, so without catch_unwind a panic in ANY tool (CLAUDE.md
            // §10.2 — a panic is a DoS) would unwind and kill the whole server,
            // dropping every in-flight background-job handle. Catch it and
            // surface it as a tool error so one bad call can't take the server
            // down. The default panic hook still logs the backtrace to stderr.
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                server.call_tool(&params.name, params.arguments)
            }))
            .unwrap_or_else(|panic| {
                let msg = panic_message(panic.as_ref());
                eprintln!("[rustynet-mcp] tool '{}' panicked: {msg}", params.name);
                tool_error(&format!(
                    "Internal error: tool '{}' panicked: {msg}",
                    params.name
                ))
            });
            let value = serde_json::to_value(&result).unwrap_or(Value::Null);
            Some(make_response(req.id.clone(), value))
        }

        "resources/list" => {
            let result = serde_json::to_value(ListResourcesResult {
                resources: server.resources(),
            })
            .unwrap_or(Value::Null);
            Some(make_response(req.id.clone(), result))
        }

        "resources/read" => {
            let uri = req
                .params
                .as_ref()
                .and_then(|p| p.get("uri"))
                .and_then(|v| v.as_str());
            match uri {
                Some(uri) => match server.read_resource(uri) {
                    Some(contents) => Some(make_response(
                        req.id.clone(),
                        serde_json::to_value(contents).unwrap_or(Value::Null),
                    )),
                    None => Some(make_error(
                        req.id.clone(),
                        INVALID_PARAMS,
                        &format!("Resource not found: {uri}"),
                    )),
                },
                None => Some(make_error(
                    req.id.clone(),
                    INVALID_PARAMS,
                    "Missing 'uri' parameter",
                )),
            }
        }

        "prompts/list" => {
            let result = serde_json::json!({ "prompts": server.prompts() });
            Some(make_response(req.id.clone(), result))
        }

        "prompts/get" => {
            let name = req
                .params
                .as_ref()
                .and_then(|p| p.get("name"))
                .and_then(|v| v.as_str());
            let arguments = req
                .params
                .as_ref()
                .and_then(|p| p.get("arguments"))
                .cloned();
            match name {
                Some(name) => match server.get_prompt(name, arguments) {
                    Some(result) => Some(make_response(
                        req.id.clone(),
                        serde_json::to_value(result).unwrap_or(Value::Null),
                    )),
                    None => Some(make_error(
                        req.id.clone(),
                        INVALID_PARAMS,
                        &format!("Prompt not found: {name}"),
                    )),
                },
                None => Some(make_error(
                    req.id.clone(),
                    INVALID_PARAMS,
                    "Missing 'name' parameter",
                )),
            }
        }

        "ping" => Some(make_response(
            req.id.clone(),
            serde_json::to_value(EmptyResult {}).unwrap_or(Value::Null),
        )),

        _ => Some(make_error(
            req.id.clone(),
            METHOD_NOT_FOUND,
            &format!("Unknown method: {}", req.method),
        )),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    struct TestServer;
    impl McpServer for TestServer {
        fn server_info(&self) -> ServerInfo {
            ServerInfo {
                name: "test".into(),
                version: "0.0.0".into(),
            }
        }
        fn tools(&self) -> Vec<Tool> {
            vec![Tool {
                name: "echo".into(),
                description: "echo".into(),
                input_schema: json_schema_object(
                    serde_json::json!({"msg": json_schema_string("message")}),
                    vec!["msg"],
                ),
            }]
        }
        fn call_tool(&self, name: &str, _arguments: Option<Value>) -> ToolCallResult {
            match name {
                "echo" => tool_success("ok"),
                "boom" => panic!("kaboom"),
                _ => tool_error("unknown"),
            }
        }
        fn resources(&self) -> Vec<Resource> {
            vec![Resource {
                uri: "test://doc".into(),
                name: "doc".into(),
                description: None,
                mime_type: Some("text/markdown".into()),
            }]
        }
        fn read_resource(&self, uri: &str) -> Option<ReadResourceResult> {
            (uri == "test://doc").then_some(ReadResourceResult {
                contents: vec![ResourceContent {
                    uri: uri.into(),
                    mime_type: Some("text/markdown".into()),
                    text: Some("hello".into()),
                }],
            })
        }
        fn prompts(&self) -> Vec<Prompt> {
            vec![Prompt {
                name: "p".into(),
                description: Some("p".into()),
                arguments: vec![],
            }]
        }
        fn get_prompt(&self, name: &str, _arguments: Option<Value>) -> Option<GetPromptResult> {
            (name == "p").then(|| prompt_text("p", "body".into()))
        }
    }

    fn req(method: &str, id: Option<Value>, params: Option<Value>) -> JsonRpcRequest {
        JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id,
            method: method.into(),
            params,
        }
    }

    #[test]
    fn tool_serializes_input_schema_as_camel_case() {
        let tool = Tool {
            name: "t".into(),
            description: "d".into(),
            input_schema: serde_json::json!({}),
        };
        let v = serde_json::to_value(&tool).unwrap();
        assert!(
            v.get("inputSchema").is_some(),
            "must be camelCase inputSchema"
        );
        assert!(v.get("input_schema").is_none());
    }

    #[test]
    fn tool_result_serializes_is_error_as_camel_case() {
        let v = serde_json::to_value(tool_error("boom")).unwrap();
        assert_eq!(v.get("isError").and_then(|b| b.as_bool()), Some(true));
        assert!(v.get("is_error").is_none());
    }

    #[test]
    fn notification_gets_no_response() {
        let resp = handle_request(&TestServer, &req("notifications/initialized", None, None));
        assert!(resp.is_none());
        // Unknown notification (no id) must also be silent.
        let resp = handle_request(&TestServer, &req("notifications/cancelled", None, None));
        assert!(resp.is_none());
    }

    #[test]
    fn unknown_method_with_id_returns_error() {
        let resp = handle_request(&TestServer, &req("bogus", Some(Value::from(1)), None)).unwrap();
        assert_eq!(resp.error.unwrap().code, METHOD_NOT_FOUND);
    }

    #[test]
    fn initialize_negotiates_supported_version_else_default() {
        let params = serde_json::json!({"protocolVersion": "2025-06-18"});
        let resp = handle_request(
            &TestServer,
            &req("initialize", Some(Value::from(1)), Some(params)),
        )
        .unwrap();
        let v = resp.result.unwrap();
        assert_eq!(v["protocolVersion"], "2025-06-18");
        // Resources + prompts advertised because TestServer provides them.
        assert!(v["capabilities"]["resources"].is_object());
        assert!(v["capabilities"]["prompts"].is_object());

        let params = serde_json::json!({"protocolVersion": "1999-01-01"});
        let resp = handle_request(
            &TestServer,
            &req("initialize", Some(Value::from(2)), Some(params)),
        )
        .unwrap();
        assert_eq!(resp.result.unwrap()["protocolVersion"], PROTOCOL_VERSION);
    }

    #[test]
    fn resources_and_prompts_roundtrip() {
        let list = handle_request(
            &TestServer,
            &req("resources/list", Some(Value::from(1)), None),
        )
        .unwrap();
        assert_eq!(list.result.unwrap()["resources"][0]["uri"], "test://doc");

        let read = handle_request(
            &TestServer,
            &req(
                "resources/read",
                Some(Value::from(1)),
                Some(serde_json::json!({"uri": "test://doc"})),
            ),
        )
        .unwrap();
        assert_eq!(read.result.unwrap()["contents"][0]["text"], "hello");

        let bad = handle_request(
            &TestServer,
            &req(
                "resources/read",
                Some(Value::from(1)),
                Some(serde_json::json!({"uri": "test://nope"})),
            ),
        )
        .unwrap();
        assert!(bad.error.is_some());

        let pget = handle_request(
            &TestServer,
            &req(
                "prompts/get",
                Some(Value::from(1)),
                Some(serde_json::json!({"name": "p"})),
            ),
        )
        .unwrap();
        assert_eq!(
            pget.result.unwrap()["messages"][0]["content"]["text"],
            "body"
        );
    }

    #[test]
    fn ping_returns_empty_result() {
        let resp = handle_request(&TestServer, &req("ping", Some(Value::from(7)), None)).unwrap();
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[test]
    fn tool_panic_is_caught_not_fatal() {
        // A panicking tool must NOT unwind out of handle_request (that would
        // kill the single-threaded server). It must come back as a tool error
        // carrying the panic message. (This intentionally logs a panic line to
        // stderr via the default hook — that is the caught panic, not a failure.)
        let resp = handle_request(
            &TestServer,
            &req(
                "tools/call",
                Some(Value::from(1)),
                Some(serde_json::json!({"name": "boom"})),
            ),
        )
        .unwrap();
        let v = resp.result.unwrap();
        assert_eq!(v["isError"], true);
        let text = v["content"][0]["text"].as_str().unwrap_or_default();
        assert!(text.contains("panicked"), "got: {text}");
        assert!(
            text.contains("kaboom"),
            "should include the panic message: {text}"
        );
    }

    #[test]
    fn truncate_output_caps_lines_and_bytes() {
        let many = (0..1000)
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let capped = truncate_output(&many, 10, 1_000_000);
        assert!(capped.contains("truncated"));
        assert!(capped.lines().count() <= 12);

        let one_huge = "x".repeat(10_000);
        let capped = truncate_output(&one_huge, 100, 500);
        assert!(capped.len() < 700);
        assert!(capped.contains("byte limit"));
    }

    #[test]
    fn run_with_timeout_captures_fast_command() {
        let outcome = run_with_timeout(
            "echo",
            &["hello-mcp"],
            Path::new("."),
            &[],
            Duration::from_secs(10),
        )
        .unwrap();
        assert!(outcome.success);
        assert!(!outcome.timed_out);
        assert!(outcome.stdout.contains("hello-mcp"));
    }

    #[test]
    fn run_with_timeout_kills_slow_command() {
        let outcome = run_with_timeout(
            "sleep",
            &["30"],
            Path::new("."),
            &[],
            Duration::from_millis(300),
        )
        .unwrap();
        assert!(outcome.timed_out, "slow command must be killed");
        assert!(!outcome.success);
    }

    #[test]
    fn spawn_logged_runs_detached_and_logs() {
        let log = std::env::temp_dir().join(format!("mcp-spawn-test-{}.log", std::process::id()));
        let mut child =
            spawn_logged("sh", &["-c", "echo detached-ok"], Path::new("."), &[], &log).unwrap();
        let status = child.wait().unwrap();
        assert!(status.success());
        let body = tail_file(&log, 10).unwrap();
        assert!(body.contains("detached-ok"), "log was: {body}");
        let _ = std::fs::remove_file(&log);
    }

    #[test]
    fn tail_file_returns_last_lines() {
        let p = std::env::temp_dir().join(format!("mcp-tail-test-{}.txt", std::process::id()));
        std::fs::write(&p, "a\nb\nc\nd\ne\n").unwrap();
        assert_eq!(tail_file(&p, 2).unwrap(), "d\ne");
        assert_eq!(tail_file(&p, 100).unwrap(), "a\nb\nc\nd\ne");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn tail_file_is_bounded_on_huge_file() {
        // ~2 MB of numbered lines; tail must stay bounded + return recent lines.
        let p = std::env::temp_dir().join(format!("mcp-tail-big-{}.txt", std::process::id()));
        let body: String = (0..200_000).map(|i| format!("line{i}\n")).collect();
        assert!(body.len() > 1_000_000);
        std::fs::write(&p, &body).unwrap();
        let tail = tail_file(&p, 3).unwrap();
        assert!(tail.contains("line199999"), "should include the last line");
        assert!(!tail.contains("line0\n"), "must not load the whole file");
        assert!(tail.len() < 5_000, "tail output must be small");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn truncate_tail_keeps_the_end() {
        // The verdict an agent needs is at the END (cargo error / test result).
        let mut s = String::new();
        for i in 0..500 {
            s.push_str(&format!("Compiling crate-{i}\n"));
        }
        s.push_str("error[E0599]: no method `foo`\ntest result: FAILED");
        let capped = truncate_tail(&s, 5, 1_000_000);
        assert!(capped.contains("test result: FAILED"), "must keep the tail");
        assert!(capped.contains("error[E0599]"));
        assert!(
            !capped.contains("Compiling crate-0\n"),
            "must drop the head"
        );
        assert!(capped.contains("truncated"));
    }

    #[test]
    fn read_file_capped_truncates() {
        let p = std::env::temp_dir().join(format!("mcp-cap-{}.txt", std::process::id()));
        std::fs::write(&p, "x".repeat(10_000)).unwrap();
        let out = read_file_capped(&p, 500).unwrap();
        assert!(out.contains("truncated"));
        assert!(out.len() < 700);
        let _ = std::fs::remove_file(&p);
    }
}
