//! Lab State MCP Server — queries and manages the UTM VM lab.
//!
//! Tools:
//! - `get_lab_status` / `get_lab_status_json` — discover all VMs
//! - `get_inventory` / `validate_inventory` / `update_inventory` — inventory ops
//! - `restart_vm` / `recover_stuck_vms` / `ensure_lab_ready` — bring the lab up
//! - `sync_repo_to_vm` / `bootstrap_vm` / `get_vm_diagnostics` — per-VM ops
//! - `setup_live_lab` / `run_live_lab` / `orchestrate_live_lab`
//!   / `diagnose_live_lab_failure` — live-lab orchestration
//! - `get_run_matrix` — read the CSV evidence ledger
//!
//! Every external command runs under a kill-on-timeout watchdog so a hung
//! `cargo`/SSH call cannot wedge the server.

#![forbid(unsafe_code)]

use rustynet_mcp::{
    CommandOutcome, McpServer, ServerInfo, Tool, ToolCallResult, json_schema_array_string,
    json_schema_boolean, json_schema_object, json_schema_string, run_server, run_with_timeout,
    text_content, tool_error, tool_success, truncate_output,
};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::time::Duration;

/// Default machine-readable inventory path (repo-relative).
const DEFAULT_INVENTORY: &str = "documents/operations/active/vm_lab_inventory.json";
/// Default report directory for live-lab tools (repo-relative).
const DEFAULT_REPORT_DIR: &str = "state/live-lab-mcp";

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
            repo_root: rustynet_mcp::repo_root(),
        }
    }

    /// Run `cargo run -p rustynet-cli -- <cli_args>` with a kill-on-timeout
    /// watchdog. `cli_args` are everything after the `--`.
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

    /// Run an `ops <subcommand>` with the default `--inventory` injected.
    fn run_ops(&self, subcommand: &str, extra_args: &[&str], timeout_secs: u64) -> ToolCallResult {
        let mut args: Vec<&str> = vec!["ops", subcommand, "--inventory", DEFAULT_INVENTORY];
        args.extend_from_slice(extra_args);
        self.run_cli(&args, &format!("ops {subcommand}"), timeout_secs)
    }

    /// Run an `ops <subcommand>` WITHOUT injecting `--inventory` (for
    /// subcommands such as `vm-lab-run-live-lab` that do not accept it).
    fn run_ops_no_inventory(
        &self,
        subcommand: &str,
        extra_args: &[&str],
        timeout_secs: u64,
    ) -> ToolCallResult {
        let mut args: Vec<&str> = vec!["ops", subcommand];
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

    /// Ensure a (possibly repo-relative) report dir exists. Returns the path
    /// string to hand to the CLI.
    fn ensure_report_dir(&self, dir: &str) -> String {
        let path = if std::path::Path::new(dir).is_absolute() {
            PathBuf::from(dir)
        } else {
            self.repo_root.join(dir)
        };
        let _ = std::fs::create_dir_all(&path);
        dir.to_string()
    }
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
                description: "Like get_lab_status but returns the full JSON discovery report. Uses `ops vm-lab-discover-local-utm --json`.".into(),
                input_schema: json_schema_object(
                    json!({
                        "report_dir": json_schema_string("Optional directory to write the discovery report into"),
                    }),
                    vec![],
                ),
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
                name: "update_inventory".into(),
                description: "Safely refresh the inventory's live IPs by running `ops vm-lab-discover-local-utm-summary --update-inventory-live-ips`. This is the ONLY supported way to update IPs — never hand-edit vm_lab_inventory.json.".into(),
                input_schema: json_schema_object(json!({}), vec![]),
            },
            Tool {
                name: "restart_vm".into(),
                description: "Restart one or more VMs. Use '--all' to restart all VMs with local UTM controllers. Use '--wait-ready' to wait for SSH readiness after restart.".into(),
                input_schema: json_schema_object(
                    json!({
                        "aliases": json_schema_array_string("VM aliases to restart, or ['--all'] for all VMs"),
                        "wait_ready": json_schema_boolean("Wait for SSH readiness after restart (default: true)"),
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
                description: "Full ensure-ready workflow: discover VMs, restart any that aren't execution-ready, wait for SSH, re-confirm. Recommended pre-flight before any live-lab run.".into(),
                input_schema: json_schema_object(json!({}), vec![]),
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
            Tool {
                name: "setup_live_lab".into(),
                description: "Generate a live-lab profile and run setup stages (discover → restart → profile). Uses `ops vm-lab-setup-live-lab`. Writes a profile you can pass to run_live_lab. Long-running; use dry_run to validate first.".into(),
                input_schema: json_schema_object(
                    json!({
                        "report_dir": json_schema_string("Report directory (default: state/live-lab-mcp)"),
                        "profile_output": json_schema_string("Optional path to write the generated profile env file"),
                        "dry_run": json_schema_boolean("Plan only, do not execute (default: false)"),
                    }),
                    vec![],
                ),
            },
            Tool {
                name: "run_live_lab".into(),
                description: "Run the full live-lab suite against an existing profile. Uses `ops vm-lab-run-live-lab` (requires --profile). Long-running; full runs need a clean working tree (the wrapper refuses commit-bound reports from a dirty tree). Use dry_run to validate.".into(),
                input_schema: json_schema_object(
                    json!({
                        "profile": json_schema_string("Path to the profile env file (from setup_live_lab)"),
                        "report_dir": json_schema_string("Optional report directory"),
                        "dry_run": json_schema_boolean("Plan only (default: false)"),
                        "skip_setup": json_schema_boolean("Skip setup stages (default: false)"),
                        "skip_gates": json_schema_boolean("Skip gate stages (default: false)"),
                        "skip_soak": json_schema_boolean("Skip soak stages (default: false)"),
                        "skip_cross_network": json_schema_boolean("Skip cross-network stages (default: false)"),
                    }),
                    vec!["profile"],
                ),
            },
            Tool {
                name: "orchestrate_live_lab".into(),
                description: "One-shot live-lab: discover → restart → setup → run → diagnose. Uses `ops vm-lab-orchestrate-live-lab`. The most complete entry point. Long-running; use dry_run or stop_after_ready to validate. Full runs need a clean working tree.".into(),
                input_schema: json_schema_object(
                    json!({
                        "report_dir": json_schema_string("Report directory (default: state/live-lab-mcp)"),
                        "dry_run": json_schema_boolean("Plan only, do not execute (default: false)"),
                        "stop_after_ready": json_schema_boolean("Stop once VMs are ready, before running stages (default: false)"),
                        "skip_gates": json_schema_boolean("Skip gate stages (default: false)"),
                        "skip_soak": json_schema_boolean("Skip soak stages (default: false)"),
                        "skip_cross_network": json_schema_boolean("Skip cross-network stages (default: false)"),
                        "windows_vm": json_schema_string("Optional Windows VM alias to include"),
                        "macos_vm": json_schema_string("Optional macOS VM alias to include"),
                        "nodes": json_schema_array_string("Optional role assignments as 'alias:role' (e.g. 'debian-headless-1:exit'), repeatable"),
                    }),
                    vec![],
                ),
            },
            Tool {
                name: "diagnose_live_lab_failure".into(),
                description: "Collect failure context from a failed live-lab run. Uses `ops vm-lab-diagnose-live-lab-failure` (requires --profile and --report-dir from the failed run).".into(),
                input_schema: json_schema_object(
                    json!({
                        "profile": json_schema_string("Path to the profile env file used by the failed run"),
                        "report_dir": json_schema_string("Report directory of the failed run"),
                        "stage": json_schema_string("Optional: specific stage name to focus on"),
                        "collect_artifacts": json_schema_boolean("Collect per-VM artifacts (default: false)"),
                    }),
                    vec!["profile", "report_dir"],
                ),
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
                let mut result = String::from("# Inventory Validation\n\n");
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
                result.push_str(&format!(
                    "**Inventory entries:** {}\n\n",
                    entries.map_or(0, |e| e.len())
                ));
                result.push_str("## Live Discovery\n\n");
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
                let aliases: Vec<String> = args
                    .and_then(|a| a.get("aliases"))
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
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
                    extra.push("--wait-ready");
                    extra.push("--ssh-identity-file");
                    extra.push(&ssh_key);
                    extra.push("--known-hosts-file");
                    extra.push(&kh);
                }
                self.run_ops("vm-lab-restart", &extra, 900)
            }

            "recover_stuck_vms" => {
                let aliases: Vec<String> = args
                    .and_then(|a| a.get("aliases"))
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
                let refs: Vec<&str> = aliases.iter().map(|s| s.as_str()).collect();
                self.run_shell_script("scripts/vm_lab/probe_and_recover_local_utm.sh", &refs, 600)
            }

            "ensure_lab_ready" => {
                let mut result = String::from("# Ensure Lab Ready\n\n");
                result.push_str("## Step 1: Discover VMs\n\n");
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
                result.push_str("## Step 3: Confirm Readiness\n\n");
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
                let mut result = format!("# VM Diagnostics: {alias}\n\n");
                result.push_str("## Daemon Status\n\n");
                let status = self.run_ops("vm-lab-status", &["--alias", alias], 300);
                if let Some(c) = status.content.first() {
                    result.push_str(&c.text);
                    result.push_str("\n\n");
                }
                result.push_str("## Diagnostic Artifacts\n\n");
                let report_dir =
                    self.ensure_report_dir(&format!("{DEFAULT_REPORT_DIR}/diag-{alias}"));
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

            "setup_live_lab" => {
                let report_dir = self
                    .ensure_report_dir(arg_str(args, "report_dir").unwrap_or(DEFAULT_REPORT_DIR));
                let ssh_key = default_ssh_identity();
                let kh = default_known_hosts();
                let mut extra: Vec<&str> = vec![
                    "--ssh-identity-file",
                    &ssh_key,
                    "--known-hosts-file",
                    &kh,
                    "--report-dir",
                    &report_dir,
                ];
                if let Some(po) = arg_str(args, "profile_output") {
                    extra.push("--profile-output");
                    extra.push(po);
                }
                if arg_bool(args, "dry_run") {
                    extra.push("--dry-run");
                }
                self.run_ops("vm-lab-setup-live-lab", &extra, 3600)
            }

            "run_live_lab" => {
                let profile = arg_str(args, "profile").unwrap_or("");
                if profile.is_empty() {
                    return tool_error("Missing required parameter: profile");
                }
                // NOTE: vm-lab-run-live-lab does not accept --inventory.
                let mut extra: Vec<&str> = vec!["--profile", profile];
                let report_dir;
                if let Some(rd) = arg_str(args, "report_dir") {
                    report_dir = self.ensure_report_dir(rd);
                    extra.push("--report-dir");
                    extra.push(&report_dir);
                }
                if arg_bool(args, "dry_run") {
                    extra.push("--dry-run");
                }
                if arg_bool(args, "skip_setup") {
                    extra.push("--skip-setup");
                }
                if arg_bool(args, "skip_gates") {
                    extra.push("--skip-gates");
                }
                if arg_bool(args, "skip_soak") {
                    extra.push("--skip-soak");
                }
                if arg_bool(args, "skip_cross_network") {
                    extra.push("--skip-cross-network");
                }
                self.run_ops_no_inventory("vm-lab-run-live-lab", &extra, 7200)
            }

            "orchestrate_live_lab" => {
                let report_dir = self
                    .ensure_report_dir(arg_str(args, "report_dir").unwrap_or(DEFAULT_REPORT_DIR));
                let ssh_key = default_ssh_identity();
                let kh = default_known_hosts();
                let mut extra: Vec<&str> = vec![
                    "--ssh-identity-file",
                    &ssh_key,
                    "--known-hosts-file",
                    &kh,
                    "--report-dir",
                    &report_dir,
                ];
                if arg_bool(args, "dry_run") {
                    extra.push("--dry-run");
                }
                if arg_bool(args, "stop_after_ready") {
                    extra.push("--stop-after-ready");
                }
                if arg_bool(args, "skip_gates") {
                    extra.push("--skip-gates");
                }
                if arg_bool(args, "skip_soak") {
                    extra.push("--skip-soak");
                }
                if arg_bool(args, "skip_cross_network") {
                    extra.push("--skip-cross-network");
                }
                if let Some(w) = arg_str(args, "windows_vm") {
                    extra.push("--windows-vm");
                    extra.push(w);
                }
                if let Some(m) = arg_str(args, "macos_vm") {
                    extra.push("--macos-vm");
                    extra.push(m);
                }
                let nodes: Vec<String> = args
                    .and_then(|a| a.get("nodes"))
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
                for n in &nodes {
                    extra.push("--node");
                    extra.push(n.as_str());
                }
                self.run_ops("vm-lab-orchestrate-live-lab", &extra, 7200)
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
