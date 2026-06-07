//! Shared MCP (Model Context Protocol) library for Rustynet agent tools.
//!
//! Implements JSON-RPC 2.0 over stdio per the MCP specification.
//! Each binary server registers tools and runs the main loop via `run_server`.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{BufRead, BufReader, Read, Write};
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
    // Use compile-time baked path (set via build.rs or default)
    if let Ok(dir) = std::env::var("RUSTYNET_REPO_BAKED") {
        let p = PathBuf::from(&dir);
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

// ── JSON-RPC 2.0 types ────────────────────────────────────────────────

pub const JSONRPC_VERSION: &str = "2.0";

/// The MCP protocol version this server prefers to speak.
pub const PROTOCOL_VERSION: &str = "2024-11-05";

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

    let stdout = outcome.stdout.trim();
    if !stdout.is_empty() {
        result.push_str(&format!(
            "### stdout\n```\n{}\n```\n\n",
            truncate_output(stdout, 200, 60_000)
        ));
    }
    let stderr = outcome.stderr.trim();
    if !stderr.is_empty() {
        result.push_str(&format!(
            "### stderr\n```\n{}\n```\n\n",
            truncate_output(stderr, 100, 40_000)
        ));
    }

    ToolCallResult {
        content: text_content(result),
        is_error: if outcome.success { None } else { Some(true) },
    }
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

fn handle_request(server: &impl McpServer, req: &JsonRpcRequest) -> Option<JsonRpcResponse> {
    eprintln!("[rustynet-mcp] <- {} id={:?}", req.method, req.id);

    // JSON-RPC notifications (no `id`) must never receive a response.
    if req.id.is_none() && req.method != "initialize" {
        return None;
    }

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

            let result = server.call_tool(&params.name, params.arguments);
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
            if name == "echo" {
                tool_success("ok")
            } else {
                tool_error("unknown")
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
}
