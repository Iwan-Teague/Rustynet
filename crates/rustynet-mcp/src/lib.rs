//! Shared MCP (Model Context Protocol) library for Rustynet agent tools.
//!
//! Implements JSON-RPC 2.0 over stdio per the MCP specification.
//! Each binary server registers tools and runs the main loop via `run_server`.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

// ── Repo root resolution ─────────────────────────────────────────────

/// Resolve the Rustynet repository root directory.
/// Checks RUSTYNET_REPO_ROOT env, then PWD, falls back to current dir.
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
pub const PROTOCOL_VERSION: &str = "2024-11-05";

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
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolsCapability {
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

#[derive(Debug, Serialize)]
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
pub struct ResourceContent {
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
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

// ── Server trait ──────────────────────────────────────────────────────

/// Implement this trait to create an MCP server.
pub trait McpServer {
    /// Server metadata returned during initialization.
    fn server_info(&self) -> ServerInfo;

    /// The list of tools this server exposes.
    fn tools(&self) -> Vec<Tool>;

    /// Handle a tool call. `arguments` is the raw JSON params.
    fn call_tool(&self, name: &str, arguments: Option<Value>) -> ToolCallResult;
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

fn handle_request(server: &impl McpServer, req: &JsonRpcRequest) -> Option<JsonRpcResponse> {
    eprintln!("[rustynet-mcp] <- {} id={:?}", req.method, req.id);
    match req.method.as_str() {
        "initialize" => {
            // Negotiate protocol version: use the client's version if provided,
            // otherwise fall back to our default.
            let client_version = req
                .params
                .as_ref()
                .and_then(|p| p.get("protocolVersion"))
                .and_then(|v| v.as_str())
                .unwrap_or(PROTOCOL_VERSION);

            let result = serde_json::to_value(InitializeResult {
                protocol_version: client_version.to_string(),
                capabilities: ServerCapabilities {
                    tools: ToolsCapability {
                        list_changed: Some(false),
                    },
                },
                server_info: server.server_info(),
            })
            .unwrap();
            Some(make_response(req.id.clone(), result))
        }

        "tools/list" => {
            let result = serde_json::to_value(ListToolsResult {
                tools: server.tools(),
            })
            .unwrap();
            Some(make_response(req.id.clone(), result))
        }

        "tools/call" => {
            let params: ToolCallParams = match req.params.clone().map(|p| serde_json::from_value(p))
            {
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
            let value = serde_json::to_value(&result).unwrap();
            Some(make_response(req.id.clone(), value))
        }

        "notifications/initialized" => {
            // No response for notifications
            None
        }

        "ping" => Some(make_response(
            req.id.clone(),
            serde_json::to_value(EmptyResult {}).unwrap(),
        )),

        _ => Some(make_error(
            req.id.clone(),
            METHOD_NOT_FOUND,
            &format!("Unknown method: {}", req.method),
        )),
    }
}
