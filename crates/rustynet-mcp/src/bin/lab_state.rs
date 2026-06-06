//! Lab State MCP Server — queries and manages the UTM VM lab.
//!
//! Tools:
//! - `get_lab_status` — discover all VMs, return reachability/readiness
//! - `get_inventory` — return the current machine-readable inventory
//! - `validate_inventory` — compare inventory against live discovery state
//! - `recover_stuck_vms` — attempt to recover VMs stuck behind killswitches
//! - `ensure_lab_ready` — full ensure-ready: discover, restart unready, wait
//! - `get_run_matrix` — get recent live-lab run status from the evidence ledger

#![forbid(unsafe_code)]

use rustynet_mcp::{
    McpServer, ServerInfo, Tool, ToolCallResult, json_schema_array_string, json_schema_object,
    json_schema_string, run_server, text_content, tool_error, tool_success,
};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let server = LabStateServer::new();
    run_server(server);
}

struct LabStateServer {
    repo_root: PathBuf,
}

impl LabStateServer {
    fn new() -> Self {
        Self {
            repo_root: PathBuf::from("."),
        }
    }

    fn run_ops(&self, subcommand: &str, extra_args: &[&str]) -> ToolCallResult {
        let mut args = vec![
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--",
            "ops",
            subcommand,
        ];
        // Default inventory path
        args.extend(&[
            "--inventory",
            "documents/operations/active/vm_lab_inventory.json",
        ]);
        args.extend(extra_args);

        let mut cmd = Command::new("cargo");
        cmd.args(&args);
        cmd.current_dir(&self.repo_root);
        cmd.env("CARGO_TERM_COLOR", "never");

        let output = match cmd.output() {
            Ok(o) => o,
            Err(e) => return tool_error(&format!("Failed to execute ops {subcommand}: {e}")),
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        let mut result = format!("# ops {subcommand}\n\n");
        result.push_str(&format!(
            "**Exit code:** {}\n\n",
            output.status.code().unwrap_or(-1)
        ));

        if output.status.success() {
            result.push_str("## ✅ PASSED\n\n");
        } else {
            result.push_str("## ❌ FAILED\n\n");
        }

        if !stdout.trim().is_empty() {
            if stdout.lines().count() > 300 {
                let head: String = stdout.lines().take(300).collect::<Vec<_>>().join("\n");
                result.push_str(&format!(
                    "```\n{head}\n... ({} more lines)\n```\n",
                    stdout.lines().count() - 300
                ));
            } else {
                result.push_str(&format!("```\n{stdout}\n```\n"));
            }
        }

        if !stderr.trim().is_empty() {
            if stderr.lines().count() > 50 {
                let head: String = stderr.lines().take(50).collect::<Vec<_>>().join("\n");
                result.push_str(&format!("### stderr\n```\n{head}\n... (truncated)\n```\n"));
            } else {
                result.push_str(&format!("### stderr\n```\n{stderr}\n```\n"));
            }
        }

        if output.status.success() {
            tool_success(&result)
        } else {
            ToolCallResult {
                content: text_content(result),
                is_error: Some(true),
            }
        }
    }

    fn run_shell_script(&self, script: &str, args: &[&str]) -> ToolCallResult {
        let script_path = self.repo_root.join(script);
        let mut cmd = Command::new("bash");
        cmd.arg(&script_path);
        cmd.args(args);
        cmd.current_dir(&self.repo_root);

        let output = match cmd.output() {
            Ok(o) => o,
            Err(e) => return tool_error(&format!("Failed to execute {script}: {e}")),
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        let mut result = format!("# {script}\n\n");
        result.push_str(&format!(
            "**Exit code:** {}\n\n",
            output.status.code().unwrap_or(-1)
        ));

        if output.status.success() {
            result.push_str("## ✅ PASSED\n\n");
        } else {
            result.push_str("## ❌ FAILED\n\n");
        }

        if !stdout.trim().is_empty() {
            result.push_str(&format!("```\n{stdout}\n```\n"));
        }
        if !stderr.trim().is_empty() {
            result.push_str(&format!("### stderr\n```\n{stderr}\n```\n"));
        }

        if output.status.success() {
            tool_success(&result)
        } else {
            ToolCallResult {
                content: text_content(result),
                is_error: Some(true),
            }
        }
    }
}

impl McpServer for LabStateServer {
    fn server_info(&self) -> ServerInfo {
        ServerInfo {
            name: "rustynet-lab-state".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        }
    }

    fn tools(&self) -> Vec<Tool> {
        vec![
            Tool {
                name: "get_lab_status".into(),
                description: "Discover all UTM VMs and return their current status: platform, live IP, SSH reachability, execution readiness. Uses `ops vm-lab-discover-local-utm-summary`.".into(),
                input_schema: json_schema_object(json!({}), vec![]),
            },
            Tool {
                name: "get_lab_status_json".into(),
                description: "Like get_lab_status but returns the full JSON discovery report for programmatic consumption. Uses `ops vm-lab-discover-local-utm`.".into(),
                input_schema: json_schema_object(json!({}), vec![]),
            },
            Tool {
                name: "get_inventory".into(),
                description: "Return the current machine-readable VM inventory from vm_lab_inventory.json — aliases, IPs, roles, OS, capabilities.".into(),
                input_schema: json_schema_object(json!({}), vec![]),
            },
            Tool {
                name: "validate_inventory".into(),
                description: "Compare the stored inventory against live VM discovery. Flags stale IPs, missing VMs, unreachable hosts.".into(),
                input_schema: json_schema_object(json!({}), vec![]),
            },
            Tool {
                name: "restart_vm".into(),
                description: "Restart one or more VMs. Use '--all' to restart all VMs with local UTM controllers. Use '--wait-ready' to wait for SSH readiness after restart.".into(),
                input_schema: json_schema_object(
                    json!({
                        "aliases": json_schema_array_string("VM aliases to restart, or ['--all'] for all VMs"),
                        "wait_ready": json!({"type": "boolean", "description": "Wait for SSH readiness after restart (default: true)"}),
                    }),
                    vec!["aliases"],
                ),
            },
            Tool {
                name: "recover_stuck_vms".into(),
                description: "Attempt to recover lab VMs that are stuck behind stale nftables killswitches (SSH port closed but VM alive). Runs the probe-and-recover script. Only works for Linux QEMU guests.".into(),
                input_schema: json_schema_object(
                    json!({
                        "aliases": json_schema_array_string("Optional: specific VM aliases to recover. Omit to recover all stuck Linux VMs."),
                    }),
                    vec![],
                ),
            },
            Tool {
                name: "ensure_lab_ready".into(),
                description: "Full ensure-ready workflow: discover VMs, restart any that aren't execution-ready, wait for SSH, update inventory. This is the recommended pre-flight before any live-lab run.".into(),
                input_schema: json_schema_object(json!({}), vec![]),
            },
            Tool {
                name: "get_run_matrix".into(),
                description: "Read the live-lab run matrix (CSV evidence ledger) and return recent runs with their OS/role/stage coverage and pass/fail status.".into(),
                input_schema: json_schema_object(
                    json!({
                        "limit": json!({"type": "integer", "description": "Number of recent rows to return (default: 20)"}),
                    }),
                    vec![],
                ),
            },
            Tool {
                name: "sync_repo_to_vm".into(),
                description: "Sync the current working tree to a VM via rsync. Uses `ops vm-lab-sync-repo`. Required before bootstrap or any code change that needs testing on a VM.".into(),
                input_schema: json_schema_object(
                    json!({
                        "alias": json_schema_string("VM alias (e.g. 'debian-headless-1', 'windows-utm-1', 'macos-utm-1')"),
                    }),
                    vec!["alias"],
                ),
            },
            Tool {
                name: "bootstrap_vm".into(),
                description: "Run a bootstrap phase on a VM. Phases: sync-source, build-release, install-release, restart-runtime, verify-runtime, smoke-service-host, tunnel-smoke, killswitch-smoke, dns-smoke, ipv6-smoke, or all. Uses `ops vm-lab-bootstrap-phase`.".into(),
                input_schema: json_schema_object(
                    json!({
                        "alias": json_schema_string("VM alias"),
                        "phase": json_schema_string("Bootstrap phase: sync-source, build-release, install-release, restart-runtime, verify-runtime, all"),
                    }),
                    vec!["alias", "phase"],
                ),
            },
            Tool {
                name: "get_vm_diagnostics".into(),
                description: "Collect diagnostics from a VM: daemon status, active tunnels, handshake context, and service state. Uses `ops vm-lab-status` + `ops vm-lab-collect-artifacts`. Use after a failed live-lab stage to triage.".into(),
                input_schema: json_schema_object(
                    json!({
                        "alias": json_schema_string("VM alias"),
                    }),
                    vec!["alias"],
                ),
            },
        ]
    }

    fn call_tool(&self, name: &str, arguments: Option<Value>) -> ToolCallResult {
        match name {
            "get_lab_status" => self.run_ops("vm-lab-discover-local-utm-summary", &[]),

            "get_lab_status_json" => {
                let mut args = vec!["--json"];
                let report_dir = arguments
                    .as_ref()
                    .and_then(|a| a.get("report_dir"))
                    .and_then(|v| v.as_str());
                if let Some(dir) = report_dir {
                    args.extend(&["--report-dir", dir]);
                }
                self.run_ops(
                    "vm-lab-discover-local-utm",
                    &args.iter().map(|s| *s).collect::<Vec<_>>(),
                )
            }

            "get_inventory" => {
                let inv_path = self
                    .repo_root
                    .join("documents/operations/active/vm_lab_inventory.json");
                match std::fs::read_to_string(&inv_path) {
                    Ok(content) => {
                        // Pretty-print the JSON
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
                // Run discovery and compare with inventory
                let mut result = String::from("# Inventory Validation\n\n");

                // 1. Check if inventory file exists
                let inv_path = self
                    .repo_root
                    .join("documents/operations/active/vm_lab_inventory.json");
                if !inv_path.exists() {
                    return tool_error(
                        "Inventory file not found: documents/operations/active/vm_lab_inventory.json",
                    );
                }

                // 2. Parse inventory
                let inv_content = match std::fs::read_to_string(&inv_path) {
                    Ok(c) => c,
                    Err(e) => return tool_error(&format!("Cannot read inventory: {e}")),
                };
                let inv: Value = match serde_json::from_str(&inv_content) {
                    Ok(v) => v,
                    Err(e) => return tool_error(&format!("Invalid inventory JSON: {e}")),
                };

                let entries = inv.get("entries").and_then(|e| e.as_array());
                result.push_str(&format!(
                    "**Inventory entries:** {}\n\n",
                    entries.map_or(0, |e| e.len())
                ));

                // 3. Run discovery
                result.push_str("## Live Discovery\n\n");
                let discovery = self.run_ops("vm-lab-discover-local-utm", &["--json"]);

                // Combine results
                result.push_str(
                    &discovery
                        .content
                        .first()
                        .map(|c| c.text.clone())
                        .unwrap_or_default(),
                );

                tool_success(&result)
            }

            "restart_vm" => {
                let aliases: Vec<String> = arguments
                    .as_ref()
                    .and_then(|a| a.get("aliases"))
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();

                let wait_ready = arguments
                    .as_ref()
                    .and_then(|a| a.get("wait_ready"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);

                if aliases.is_empty() {
                    return tool_error("At least one alias is required");
                }

                let mut args = Vec::new();
                if aliases.len() == 1 && aliases[0] == "--all" {
                    args.push("--all");
                } else {
                    for alias in &aliases {
                        args.push("--alias");
                        args.push(alias.as_str());
                    }
                }
                if wait_ready {
                    args.push("--wait-ready");
                    args.push("--ssh-identity-file");
                    let ssh_key = expand_tilde("~/.ssh/rustynet_lab_ed25519");
                    args.push(&ssh_key);
                    args.push("--known-hosts-file");
                    let kh = expand_tilde("~/.ssh/known_hosts");
                    args.push(&kh);
                }

                self.run_ops("vm-lab-restart", &args)
            }

            "recover_stuck_vms" => {
                let aliases: Vec<String> = arguments
                    .as_ref()
                    .and_then(|a| a.get("aliases"))
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();

                let mut args = Vec::new();
                if !aliases.is_empty() {
                    for alias in &aliases {
                        args.push(alias.as_str());
                    }
                }

                self.run_shell_script("scripts/vm_lab/probe_and_recover_local_utm.sh", &args)
            }

            "ensure_lab_ready" => {
                let mut result = String::from("# Ensure Lab Ready\n\n");

                // Step 1: Discover
                result.push_str("## Step 1: Discover VMs\n\n");
                let discover = self.run_ops("vm-lab-discover-local-utm-summary", &[]);
                if let Some(c) = discover.content.first() {
                    result.push_str(&c.text);
                    result.push_str("\n\n");
                }

                // Step 2: Restart unready VMs
                result.push_str("## Step 2: Restart + Wait Ready\n\n");
                let restart = self.run_ops(
                    "vm-lab-restart",
                    &[
                        "--all",
                        "--wait-ready",
                        "--ssh-identity-file",
                        &expand_tilde("~/.ssh/rustynet_lab_ed25519"),
                        "--known-hosts-file",
                        &expand_tilde("~/.ssh/known_hosts"),
                    ],
                );
                if let Some(c) = restart.content.first() {
                    result.push_str(&c.text);
                    result.push_str("\n\n");
                }

                // Step 3: Re-discover to confirm
                result.push_str("## Step 3: Confirm Readiness\n\n");
                let confirm = self.run_ops("vm-lab-discover-local-utm-summary", &[]);
                if let Some(c) = confirm.content.first() {
                    result.push_str(&c.text);
                }

                tool_success(&result)
            }

            "get_run_matrix" => {
                let limit = arguments
                    .as_ref()
                    .and_then(|a| a.get("limit"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(20) as usize;

                let matrix_path = self
                    .repo_root
                    .join("documents/operations/live_lab_run_matrix.csv");
                match std::fs::read_to_string(&matrix_path) {
                    Ok(content) => {
                        let lines: Vec<&str> = content.lines().collect();
                        let total = lines.len().saturating_sub(1); // minus header

                        let mut result = format!("# Live Lab Run Matrix ({total} total runs)\n\n");

                        if lines.is_empty() {
                            result.push_str("Matrix is empty.\n");
                        } else {
                            // Show header
                            result.push_str(&format!("```\n{}\n```\n\n", lines[0]));

                            // Show recent rows
                            let start = if lines.len() > limit + 1 {
                                lines.len() - limit - 1
                            } else {
                                1
                            };
                            result.push_str(&format!("## Last {} runs\n\n```\n", limit));
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

            "sync_repo_to_vm" => {
                let alias = arguments
                    .as_ref()
                    .and_then(|a| a.get("alias"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if alias.is_empty() {
                    return tool_error("Missing required parameter: alias");
                }
                self.run_ops("vm-lab-sync-repo", &["--alias", alias])
            }

            "bootstrap_vm" => {
                let alias = arguments
                    .as_ref()
                    .and_then(|a| a.get("alias"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let phase = arguments
                    .as_ref()
                    .and_then(|a| a.get("phase"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if alias.is_empty() || phase.is_empty() {
                    return tool_error("Missing required parameters: alias and phase");
                }
                self.run_ops(
                    "vm-lab-bootstrap-phase",
                    &["--alias", alias, "--phase", phase],
                )
            }

            "get_vm_diagnostics" => {
                let alias = arguments
                    .as_ref()
                    .and_then(|a| a.get("alias"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if alias.is_empty() {
                    return tool_error("Missing required parameter: alias");
                }

                let mut result = format!("# VM Diagnostics: {alias}\n\n");

                // Step 1: VM status
                result.push_str("## Daemon Status\n\n");
                let status = self.run_ops("vm-lab-status", &["--alias", alias]);
                if let Some(c) = status.content.first() {
                    result.push_str(&c.text);
                    result.push_str("\n\n");
                }

                // Step 2: Collect artifacts
                result.push_str("## Diagnostic Artifacts\n\n");
                let report_dir = format!("/tmp/rn_diag_{alias}");
                let _ = std::fs::create_dir_all(&report_dir);
                let artifacts = self.run_ops(
                    "vm-lab-collect-artifacts",
                    &["--alias", alias, "--report-dir", &report_dir],
                );
                if let Some(c) = artifacts.content.first() {
                    result.push_str(&c.text);
                }

                tool_success(&result)
            }

            _ => tool_error(&format!("Unknown tool: {name}")),
        }
    }
}

fn expand_tilde(path: &str) -> String {
    if path.starts_with("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{}/{}", home, &path[2..]);
        }
    }
    path.to_string()
}
