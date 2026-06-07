//! Gate Runner MCP Server — runs Rustynet quality gates on demand.
//!
//! Tools:
//! - `run_gates` — run the full gate suite via xtask (fmt → check → clippy → test)
//! - `run_check` — cargo check
//! - `run_fmt` — cargo fmt --check
//! - `run_clippy` — cargo clippy
//! - `run_test` — cargo test (specific scope or all)
//! - `run_security_audit` — cargo audit + cargo deny
//! - `list_gate_scripts` — list available phase-specific CI gate scripts

#![forbid(unsafe_code)]

use rustynet_mcp::{
    McpServer, ServerInfo, Tool, ToolCallResult, json_schema_boolean, json_schema_object,
    json_schema_string, outcome_to_result, run_server, run_with_timeout, tool_error, tool_success,
    truncate_output,
};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::time::Duration;

fn main() {
    let server = GateRunnerServer::new();
    run_server(server);
}

struct GateRunnerServer {
    repo_root: PathBuf,
}

impl GateRunnerServer {
    fn new() -> Self {
        Self {
            repo_root: rustynet_mcp::repo_root(),
        }
    }

    /// Run a command in the repo root with a hard timeout. The child is killed
    /// (and reaped) on timeout so a hung cargo invocation cannot keep holding
    /// the `target/` build lock and wedge later gate calls.
    fn run_command(&self, program: &str, args: &[&str], timeout_secs: u64) -> ToolCallResult {
        let title = format!("`{} {}`", program, args.join(" "));
        match run_with_timeout(
            program,
            args,
            &self.repo_root,
            &[("CARGO_TERM_COLOR", "never")],
            Duration::from_secs(timeout_secs),
        ) {
            Ok(outcome) => outcome_to_result(&title, &outcome),
            Err(e) => tool_error(&e),
        }
    }

    fn run_xtask(&self, extra_args: &[&str]) -> ToolCallResult {
        let mut args = vec!["run", "-p", "rustynet-xtask", "--", "gates"];
        args.extend(extra_args);
        self.run_command("cargo", &args, 600)
    }
}

impl McpServer for GateRunnerServer {
    fn server_info(&self) -> ServerInfo {
        ServerInfo {
            name: "rustynet-gate-runner".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        }
    }

    fn tools(&self) -> Vec<Tool> {
        vec![
            Tool {
                name: "run_gates".into(),
                description: "Run the full quality gate suite via xtask: fmt → check → clippy → test. Stops at first failure. Use --skip-test to skip the slow test stage. Specify scope with --scope (e.g. '-p rustynet-cli').".into(),
                input_schema: json_schema_object(
                    json!({
                        "skip_test": json_schema_boolean("Skip the test stage (default: false)"),
                        "scope": json_schema_string("Optional cargo scope, e.g. '-p rustynet-cli' or '--workspace'"),
                    }),
                    vec![],
                ),
            },
            Tool {
                name: "run_check".into(),
                description: "Run `cargo check --workspace --all-targets --all-features`. Fast compilation check without codegen.".into(),
                input_schema: json_schema_object(
                    json!({
                        "scope": json_schema_string("Optional cargo scope, e.g. '-p rustynet-cli'"),
                    }),
                    vec![],
                ),
            },
            Tool {
                name: "run_fmt".into(),
                description: "Run `cargo fmt --all -- --check`. Verifies code formatting.".into(),
                input_schema: json_schema_object(json!({}), vec![]),
            },
            Tool {
                name: "run_clippy".into(),
                description: "Run `cargo clippy --workspace --all-targets --all-features -- -D warnings`. Lint checking with warnings-as-errors.".into(),
                input_schema: json_schema_object(
                    json!({
                        "scope": json_schema_string("Optional cargo scope"),
                    }),
                    vec![],
                ),
            },
            Tool {
                name: "run_test".into(),
                description: "Run `cargo test`. Specify scope to run a subset (e.g. '-p rustynet-control' or a specific test name).".into(),
                input_schema: json_schema_object(
                    json!({
                        "scope": json_schema_string("Cargo scope, e.g. '-p rustynetd' or '--test gossip_three_peer_mesh'"),
                        "nocapture": json_schema_boolean("Show test output (-- --nocapture)"),
                    }),
                    vec![],
                ),
            },
            Tool {
                name: "run_security_audit".into(),
                description: "Run `cargo audit` and `cargo deny check bans licenses sources advisories`. Checks for known vulnerabilities and dependency policy violations.".into(),
                input_schema: json_schema_object(json!({}), vec![]),
            },
            Tool {
                name: "list_gate_scripts".into(),
                description: "List all available phase-specific CI gate shell scripts under scripts/ci/ with their descriptions.".into(),
                input_schema: json_schema_object(json!({}), vec![]),
            },
            Tool {
                name: "run_gate_script".into(),
                description: "Run a specific phase gate script from scripts/ci/. Use list_gate_scripts to see available scripts.".into(),
                input_schema: json_schema_object(
                    json!({
                        "script": json_schema_string("Script name, e.g. 'phase9_gates.sh' or 'membership_gates.sh'"),
                    }),
                    vec!["script"],
                ),
            },
            Tool {
                name: "run_build".into(),
                description: "Run `cargo build` to compile binaries. Use --release for optimized builds. Specify scope to build a subset (e.g. '-p rustynetd').".into(),
                input_schema: json_schema_object(
                    json!({
                        "release": json_schema_boolean("Build with optimizations (--release)"),
                        "scope": json_schema_string("Optional cargo scope, e.g. '-p rustynetd'"),
                    }),
                    vec![],
                ),
            },
        ]
    }

    fn call_tool(&self, name: &str, arguments: Option<Value>) -> ToolCallResult {
        match name {
            "run_gates" => {
                let skip_test = arguments
                    .as_ref()
                    .and_then(|a| a.get("skip_test"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let scope = arguments
                    .as_ref()
                    .and_then(|a| a.get("scope"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                let mut extra_args = Vec::new();
                if skip_test {
                    extra_args.push("--skip-test");
                }
                if !scope.is_empty() {
                    extra_args.push(scope);
                }
                self.run_xtask(&extra_args)
            }

            "run_check" => {
                let scope = arguments
                    .as_ref()
                    .and_then(|a| a.get("scope"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("--workspace");

                let mut args = vec!["check"];
                if scope == "--workspace" || scope.is_empty() {
                    args.extend(&["--workspace", "--all-targets", "--all-features"]);
                } else {
                    // Parse the scope as cargo args
                    args.extend(scope.split_whitespace().collect::<Vec<_>>());
                    args.extend(&["--all-targets", "--all-features"]);
                }
                self.run_command("cargo", &args, 300)
            }

            "run_fmt" => self.run_command("cargo", &["fmt", "--all", "--", "--check"], 120),

            "run_clippy" => {
                let scope = arguments
                    .as_ref()
                    .and_then(|a| a.get("scope"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("--workspace");

                let mut args = vec!["clippy"];
                if scope == "--workspace" || scope.is_empty() {
                    args.extend(&[
                        "--workspace",
                        "--all-targets",
                        "--all-features",
                        "--",
                        "-D",
                        "warnings",
                    ]);
                } else {
                    args.extend(scope.split_whitespace().collect::<Vec<_>>());
                    args.extend(&["--all-targets", "--all-features", "--", "-D", "warnings"]);
                }
                self.run_command("cargo", &args, 300)
            }

            "run_test" => {
                let scope = arguments
                    .as_ref()
                    .and_then(|a| a.get("scope"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("--workspace");
                let nocapture = arguments
                    .as_ref()
                    .and_then(|a| a.get("nocapture"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                let mut args = vec!["test"];
                if scope == "--workspace" || scope.is_empty() {
                    args.extend(&["--workspace", "--all-targets", "--all-features"]);
                } else {
                    args.extend(scope.split_whitespace().collect::<Vec<_>>());
                }
                if nocapture {
                    args.push("--");
                    args.push("--nocapture");
                }
                self.run_command("cargo", &args, 600)
            }

            "run_security_audit" => {
                let env = [("CARGO_TERM_COLOR", "never")];
                let mut results = Vec::new();
                let mut failed = false;

                for (heading, cmd_args, timeout) in [
                    ("cargo audit", &["audit", "--deny", "warnings"][..], 300u64),
                    (
                        "cargo deny",
                        &["deny", "check", "bans", "licenses", "sources", "advisories"][..],
                        300,
                    ),
                ] {
                    match run_with_timeout(
                        "cargo",
                        cmd_args,
                        &self.repo_root,
                        &env,
                        Duration::from_secs(timeout),
                    ) {
                        Ok(o) => {
                            if !o.success {
                                failed = true;
                            }
                            let banner = if o.timed_out {
                                "⏱️ TIMED OUT"
                            } else if o.success {
                                "✅"
                            } else {
                                "❌"
                            };
                            let body = format!("{}\n{}", o.stdout.trim(), o.stderr.trim());
                            results.push(format!(
                                "## {heading} {banner}\n```\n{}\n```\n",
                                truncate_output(body.trim(), 150, 40_000)
                            ));
                        }
                        Err(e) => {
                            failed = true;
                            results.push(format!("## {heading} ❌\n{e}\n"));
                        }
                    }
                }

                if failed {
                    ToolCallResult {
                        content: rustynet_mcp::text_content(results.join("\n")),
                        is_error: Some(true),
                    }
                } else {
                    tool_success(&results.join("\n"))
                }
            }

            "list_gate_scripts" => {
                let scripts_dir = self.repo_root.join("scripts").join("ci");
                let mut result = String::from("# Available CI Gate Scripts\n\n");

                match std::fs::read_dir(&scripts_dir) {
                    Ok(entries) => {
                        let mut scripts: Vec<String> = entries
                            .filter_map(|e| e.ok())
                            .filter(|e| e.path().extension().is_some_and(|ext| ext == "sh"))
                            .map(|e| {
                                let name = e.file_name().to_string_lossy().to_string();
                                // Try to read first comment line as description
                                let desc = std::fs::read_to_string(e.path())
                                    .ok()
                                    .and_then(|c| {
                                        c.lines()
                                            .filter(|l| l.starts_with("#"))
                                            .nth(1)
                                            .map(|l| l.trim_start_matches("# ").to_string())
                                    })
                                    .unwrap_or_else(|| "(no description)".into());
                                format!("- **`{name}`** — {desc}")
                            })
                            .collect();
                        scripts.sort();
                        result.push_str(&scripts.join("\n"));
                    }
                    Err(e) => {
                        result.push_str(&format!("Cannot list scripts: {e}"));
                    }
                }

                result.push_str("\n\n## Key Scripts\n\n");
                result.push_str("- `phase9_gates.sh` — Phase 9 release-readiness gates\n");
                result.push_str("- `phase10_gates.sh` — Phase 10 dataplane enforcement gates\n");
                result.push_str("- `membership_gates.sh` — Membership consensus gates\n");
                result.push_str("- `security_regression_gates.sh` — Security regression tests\n");
                result.push_str("- `secrets_hygiene_gates.sh` — Secret redaction / key hygiene\n");
                result.push_str("- `anchor_role_gates.sh` — Anchor node role validation\n");
                result.push_str(
                    "- `cross_platform_role_gates.sh` — Cross-platform role transition tests\n",
                );
                result.push_str("- `no_leak_dataplane_gate.sh` — Tunnel/DNS leak prevention\n");
                result.push_str(
                    "- `supply_chain_integrity_gates.sh` — SBOM + signing verification\n",
                );

                tool_success(&result)
            }

            "run_gate_script" => {
                let script = arguments
                    .and_then(|a| a.get("script").cloned())
                    .and_then(|v| v.as_str().map(String::from))
                    .unwrap_or_default();

                if script.is_empty() {
                    return tool_error("Missing required parameter: script");
                }

                // Security: only allow scripts from scripts/ci/
                let script_path = self.repo_root.join("scripts").join("ci").join(&script);
                if !script_path.exists() {
                    return tool_error(&format!("Script not found: scripts/ci/{script}"));
                }

                // Canonicalize to prevent traversal
                let canonical = match script_path.canonicalize() {
                    Ok(p) => p,
                    Err(e) => return tool_error(&format!("Cannot resolve script path: {e}")),
                };
                let ci_dir = match self.repo_root.join("scripts").join("ci").canonicalize() {
                    Ok(p) => p,
                    Err(e) => return tool_error(&format!("Cannot resolve scripts/ci: {e}")),
                };
                if !canonical.starts_with(&ci_dir) {
                    return tool_error("Script path escapes scripts/ci/ directory");
                }

                self.run_command("bash", &[&script_path.to_string_lossy()], 600)
            }

            "run_build" => {
                let release = arguments
                    .as_ref()
                    .and_then(|a| a.get("release"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let scope = arguments
                    .as_ref()
                    .and_then(|a| a.get("scope"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                let mut args = vec!["build"];
                if release {
                    args.push("--release");
                }
                if scope.is_empty() {
                    args.extend(&["--workspace", "--all-targets", "--all-features"]);
                } else {
                    args.extend(scope.split_whitespace().collect::<Vec<_>>());
                }
                self.run_command("cargo", &args, 600)
            }

            _ => tool_error(&format!("Unknown tool: {name}")),
        }
    }
}

// ── Appended: run_build tool ─────────────────────────────────────────

// The tool definition is inserted into the tools() Vec. The handler is in call_tool.
