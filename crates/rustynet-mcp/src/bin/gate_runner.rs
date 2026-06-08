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
    McpServer, ServerInfo, Tool, ToolCallResult, json_schema_array_string, json_schema_boolean,
    json_schema_object, json_schema_string, outcome_to_result, run_server, run_with_timeout,
    text_content, tool_error, tool_success, truncate_output, truncate_tail,
};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::time::Duration;

/// Local security-critical gate scripts (no live lab needed) — the "did I break
/// security?" suite to run after touching trust / dataplane / crypto / policy
/// code. Each is verified to run locally (no ssh/utmctl/vm-lab dependency).
const SECURITY_GATES: &[&str] = &[
    "secrets_hygiene_gates.sh",
    "check_backend_boundary_leakage.sh",
    "no_leak_dataplane_gate.sh",
    "security_regression_gates.sh",
    "supply_chain_integrity_gates.sh",
    "role_auth_matrix_gates.sh",
    "check_dependency_exceptions.sh",
    "anchor_secret_redaction_gates.sh",
    "traversal_adversarial_gates.sh",
    "active_network_security_gates.sh",
];

/// Topical category for a gate script (by name + lab-dependence), so the agent
/// can pick the right gates instead of scanning a flat list.
fn gate_category(name: &str, is_lab: bool) -> &'static str {
    if is_lab {
        return "lab-dependent (needs VMs)";
    }
    if SECURITY_GATES.contains(&name)
        || [
            "secret",
            "leak",
            "security",
            "redaction",
            "supply_chain",
            "dependency",
            "boundary",
            "traversal",
            "auth_matrix",
        ]
        .iter()
        .any(|k| name.contains(k))
    {
        "security"
    } else if ["role", "exit", "anchor"].iter().any(|k| name.contains(k)) {
        "role / platform"
    } else if name.contains("phase") {
        "phase"
    } else if [
        "release",
        "readiness",
        "fresh_install",
        "os_matrix",
        "perf",
        "regression_coverage",
    ]
    .iter()
    .any(|k| name.contains(k))
    {
        "release / readiness"
    } else {
        "other"
    }
}

/// True if a gate script needs the live VM lab (ssh/utmctl/inventory) — those
/// can't run in a plain local gate pass.
fn script_needs_lab(body: &str) -> bool {
    [
        "utmctl",
        "vm-lab",
        "vm_lab",
        "ssh_target",
        "live_lab",
        "live-lab",
        "ssh ",
    ]
    .iter()
    .any(|k| body.contains(k))
}

fn main() {
    let server = GateRunnerServer::new();
    run_server(server);
}

/// Reject cargo flags in a `scope` that could turn a gate into arbitrary code
/// execution (`--config` can set a custom runner) or redirect the build.
/// Defense-in-depth: scope is a trusted-agent input, but the project forbids
/// such surfaces on principle. Returns the first offending token, if any.
fn unsafe_scope_token(scope: &str) -> Option<&str> {
    scope.split_whitespace().find(|t| {
        t.starts_with("--config")
            || t.starts_with("--target-dir")
            || t.starts_with("--manifest-path")
    })
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

    /// Crates changed vs HEAD (including staged), as a cargo scope like
    /// "-p rustynet-control -p rustynet-policy". Empty if no crate changes.
    fn changed_crate_scope(&self) -> String {
        let mut crates = std::collections::BTreeSet::new();
        for diff_args in [
            ["diff", "--name-only", "HEAD"],
            ["diff", "--cached", "--name-only"],
        ] {
            if let Ok(o) = run_with_timeout(
                "git",
                &diff_args,
                &self.repo_root,
                &[],
                Duration::from_secs(30),
            ) {
                for line in o.stdout.lines() {
                    let mut parts = line.split('/');
                    if parts.next() == Some("crates")
                        && let Some(name) = parts.next()
                    {
                        crates.insert(name.to_string());
                    }
                }
            }
        }
        crates
            .iter()
            .map(|c| format!("-p {c}"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Validate a gate script name resolves to a real file confined to
    /// scripts/ci/ (no traversal). Returns the canonical path.
    fn resolve_gate_script(&self, script: &str) -> Result<PathBuf, String> {
        if script.is_empty() {
            return Err("empty script name".into());
        }
        let path = self.repo_root.join("scripts").join("ci").join(script);
        if !path.exists() {
            return Err(format!("not found: scripts/ci/{script}"));
        }
        let canonical = path
            .canonicalize()
            .map_err(|e| format!("cannot resolve {script}: {e}"))?;
        let ci_dir = self
            .repo_root
            .join("scripts")
            .join("ci")
            .canonicalize()
            .map_err(|e| format!("cannot resolve scripts/ci: {e}"))?;
        if !canonical.starts_with(&ci_dir) {
            return Err(format!("escapes scripts/ci/: {script}"));
        }
        Ok(canonical)
    }

    /// Run a set of gate scripts sequentially, aggregating results. Passes are
    /// reported terse; failures include the tail of their output (gate errors
    /// land at the END). Returns (markdown_body, passed_count, failed_names).
    fn run_scripts_collect(
        &self,
        scripts: &[String],
        per_timeout: u64,
    ) -> (String, u32, Vec<String>) {
        let mut body = String::new();
        let mut passed = 0u32;
        let mut failed: Vec<String> = Vec::new();
        for script in scripts {
            let path = match self.resolve_gate_script(script) {
                Ok(p) => p,
                Err(e) => {
                    body.push_str(&format!("## {script} ❌ {e}\n\n"));
                    failed.push(script.clone());
                    continue;
                }
            };
            match run_with_timeout(
                "bash",
                &[&path.to_string_lossy()],
                &self.repo_root,
                &[("CARGO_TERM_COLOR", "never")],
                Duration::from_secs(per_timeout),
            ) {
                Ok(o) => {
                    let banner = if o.timed_out {
                        "⏱️ TIMED OUT"
                    } else if o.success {
                        "✅"
                    } else {
                        "❌"
                    };
                    if o.success {
                        passed += 1;
                        body.push_str(&format!("## {script} {banner}\n\n"));
                    } else {
                        failed.push(script.clone());
                        let combined = format!("{}\n{}", o.stdout.trim(), o.stderr.trim());
                        body.push_str(&format!(
                            "## {script} {banner}\n```\n{}\n```\n\n",
                            truncate_tail(combined.trim(), 80, 12_000)
                        ));
                    }
                }
                Err(e) => {
                    failed.push(script.clone());
                    body.push_str(&format!("## {script} ❌ {e}\n\n"));
                }
            }
        }
        (body, passed, failed)
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
                description: "Run the quality gate suite via xtask: fmt → check → clippy → test. Stops at first failure. skip_test skips the slow test stage. scope sets a cargo scope (e.g. '-p rustynet-cli'). changed_only auto-scopes to the crates changed vs HEAD (incl. staged) — fast inner loop after a patch.".into(),
                input_schema: json_schema_object(
                    json!({
                        "skip_test": json_schema_boolean("Skip the test stage (default: false)"),
                        "scope": json_schema_string("Optional cargo scope, e.g. '-p rustynet-cli' or '--workspace'"),
                        "changed_only": json_schema_boolean("Auto-scope to crates changed vs HEAD (default: false). Ignored if scope is given."),
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
                name: "run_security_gates".into(),
                description: "Run the LOCAL security-critical gate suite in one call — the 'did I break security?' check for a security-first project. Bundles secrets-hygiene, backend-boundary-leakage, no-leak-dataplane, security-regression, supply-chain-integrity, role-auth-matrix, dependency-exceptions, anchor-secret-redaction, traversal-adversarial, and active-network-security gates, plus cargo audit/deny, with a single aggregated pass/fail verdict (failures show their output tail). Run after touching trust / dataplane / crypto / policy / membership code. Can take several minutes (each gate is killed on its own timeout). Set skip_audit to omit audit/deny.".into(),
                input_schema: json_schema_object(
                    json!({"skip_audit": json_schema_boolean("Skip cargo audit + cargo deny (default: false)")}),
                    vec![],
                ),
            },
            Tool {
                name: "run_gate_scripts".into(),
                description: "Run a chosen SET of CI gate scripts (from scripts/ci/) in one call, with an aggregated pass/fail verdict — e.g. a whole phase's gates, or a hand-picked group, without N round-trips. Each runs under its own kill-on-timeout watchdog; failures include their output tail. Use list_gate_scripts to see names + categories. For the security set prefer run_security_gates.".into(),
                input_schema: json_schema_object(
                    json!({"scripts": json_schema_array_string("Gate script names, e.g. ['phase9_gates.sh','phase10_gates.sh']")}),
                    vec!["scripts"],
                ),
            },
            Tool {
                name: "list_gate_scripts".into(),
                description: "List the CI gate scripts under scripts/ci/, grouped by category (security / role-platform / phase / release / lab-dependent / other) and flagged when they need the live VM lab — so you can pick the right gates for a change. Run a set with run_gate_scripts, or the curated security set with run_security_gates.".into(),
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
                let explicit_scope = arguments
                    .as_ref()
                    .and_then(|a| a.get("scope"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let changed_only = arguments
                    .as_ref()
                    .and_then(|a| a.get("changed_only"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                // Explicit scope wins; else changed_only computes it from git.
                let scope: String = if !explicit_scope.is_empty() {
                    explicit_scope.to_string()
                } else if changed_only {
                    self.changed_crate_scope()
                } else {
                    String::new()
                };
                if let Some(bad) = unsafe_scope_token(&scope) {
                    return tool_error(&format!(
                        "Refusing scope token '{bad}': --config/--target-dir/--manifest-path are not allowed."
                    ));
                }

                if changed_only && explicit_scope.is_empty() && scope.is_empty() {
                    return tool_success(
                        "# run_gates (changed_only)\n\nNo changed crates detected vs HEAD — nothing to gate. Patch some code first, or run without changed_only for the full workspace.",
                    );
                }

                let mut extra_args: Vec<&str> = Vec::new();
                if skip_test {
                    extra_args.push("--skip-test");
                }
                // Split the scope into individual cargo args (supports multiple -p).
                for tok in scope.split_whitespace() {
                    extra_args.push(tok);
                }
                self.run_xtask(&extra_args)
            }

            "run_check" => {
                let scope = arguments
                    .as_ref()
                    .and_then(|a| a.get("scope"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("--workspace");
                if let Some(bad) = unsafe_scope_token(scope) {
                    return tool_error(&format!(
                        "Refusing scope token '{bad}': --config/--target-dir/--manifest-path are not allowed."
                    ));
                }

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
                if let Some(bad) = unsafe_scope_token(scope) {
                    return tool_error(&format!(
                        "Refusing scope token '{bad}': --config/--target-dir/--manifest-path are not allowed."
                    ));
                }

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
                if let Some(bad) = unsafe_scope_token(scope) {
                    return tool_error(&format!(
                        "Refusing scope token '{bad}': --config/--target-dir/--manifest-path are not allowed."
                    ));
                }

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

            "run_security_gates" => {
                let skip_audit = arguments
                    .as_ref()
                    .and_then(|a| a.get("skip_audit"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let gates: Vec<String> = SECURITY_GATES.iter().map(|s| s.to_string()).collect();
                let (mut body, mut passed, mut failed) = self.run_scripts_collect(&gates, 300);
                if !skip_audit {
                    for (heading, cmd_args) in [
                        ("cargo audit", &["audit", "--deny", "warnings"][..]),
                        (
                            "cargo deny",
                            &["deny", "check", "bans", "licenses", "sources", "advisories"][..],
                        ),
                    ] {
                        match run_with_timeout(
                            "cargo",
                            cmd_args,
                            &self.repo_root,
                            &[("CARGO_TERM_COLOR", "never")],
                            Duration::from_secs(300),
                        ) {
                            Ok(o) if o.success => {
                                passed += 1;
                                body.push_str(&format!("## {heading} ✅\n\n"));
                            }
                            Ok(o) => {
                                failed.push(heading.to_string());
                                let combined = format!("{}\n{}", o.stdout.trim(), o.stderr.trim());
                                body.push_str(&format!(
                                    "## {heading} ❌\n```\n{}\n```\n\n",
                                    truncate_tail(combined.trim(), 80, 12_000)
                                ));
                            }
                            Err(e) => {
                                failed.push(heading.to_string());
                                body.push_str(&format!("## {heading} ❌ {e}\n\n"));
                            }
                        }
                    }
                }
                let verdict = if failed.is_empty() {
                    format!("## ✅ SECURITY GATES PASSED ({passed}/{passed})\n")
                } else {
                    format!(
                        "## ❌ SECURITY GATES FAILED — {} failing: {}\n(passed {passed})\n\nFix the root cause before claiming the change is safe.\n",
                        failed.len(),
                        failed.join(", ")
                    )
                };
                let out = format!("# Security gate suite\n\n{body}{verdict}");
                ToolCallResult {
                    content: text_content(out),
                    is_error: if failed.is_empty() { None } else { Some(true) },
                }
            }

            "run_gate_scripts" => {
                let scripts: Vec<String> = arguments
                    .as_ref()
                    .and_then(|a| a.get("scripts"))
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
                if scripts.is_empty() {
                    return tool_error(
                        "Provide a non-empty 'scripts' array (see list_gate_scripts)",
                    );
                }
                let (body, passed, failed) = self.run_scripts_collect(&scripts, 600);
                let verdict = if failed.is_empty() {
                    format!("## ✅ ALL {passed} PASSED\n")
                } else {
                    format!(
                        "## ❌ {} FAILED: {} (passed {passed})\n",
                        failed.len(),
                        failed.join(", ")
                    )
                };
                let out = format!("# Gate scripts\n\n{body}{verdict}");
                ToolCallResult {
                    content: text_content(out),
                    is_error: if failed.is_empty() { None } else { Some(true) },
                }
            }

            "list_gate_scripts" => {
                let scripts_dir = self.repo_root.join("scripts").join("ci");
                let entries = match std::fs::read_dir(&scripts_dir) {
                    Ok(e) => e,
                    Err(e) => return tool_error(&format!("Cannot list scripts: {e}")),
                };
                // (category, name, desc, is_lab)
                let mut rows: Vec<(&'static str, String, String, bool)> = Vec::new();
                for entry in entries.filter_map(|e| e.ok()) {
                    let path = entry.path();
                    if path.extension().is_none_or(|ext| ext != "sh") {
                        continue;
                    }
                    let name = entry.file_name().to_string_lossy().to_string();
                    let content = std::fs::read_to_string(&path).unwrap_or_default();
                    let is_lab = script_needs_lab(&content);
                    let desc = content
                        .lines()
                        .filter(|l| l.starts_with('#'))
                        .nth(1)
                        .map(|l| {
                            l.trim_start_matches("# ")
                                .trim_start_matches('#')
                                .trim()
                                .to_string()
                        })
                        .filter(|d| !d.is_empty())
                        .unwrap_or_else(|| "(no description)".into());
                    rows.push((gate_category(&name, is_lab), name, desc, is_lab));
                }
                rows.sort_by(|a, b| a.1.cmp(&b.1));
                let mut result = format!("# CI Gate Scripts ({} total)\n", rows.len());
                for cat in [
                    "security",
                    "role / platform",
                    "phase",
                    "release / readiness",
                    "lab-dependent (needs VMs)",
                    "other",
                ] {
                    let in_cat: Vec<&(&str, String, String, bool)> =
                        rows.iter().filter(|r| r.0 == cat).collect();
                    if in_cat.is_empty() {
                        continue;
                    }
                    result.push_str(&format!("\n## {cat} ({})\n", in_cat.len()));
                    for (_, name, desc, _) in in_cat {
                        result.push_str(&format!("- **`{name}`** — {desc}\n"));
                    }
                }
                result.push_str(
                    "\n_Run the security set with `run_security_gates`; run any chosen set with `run_gate_scripts`. lab-dependent gates need a live VM lab (use the lab-state server)._\n",
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
                if let Some(bad) = unsafe_scope_token(scope) {
                    return tool_error(&format!(
                        "Refusing scope token '{bad}': --config/--target-dir/--manifest-path are not allowed."
                    ));
                }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsafe_scope_token_blocks_cargo_injection() {
        assert!(unsafe_scope_token("-p rustynet-cli").is_none());
        assert!(unsafe_scope_token("--workspace --all-features").is_none());
        assert_eq!(
            unsafe_scope_token("--config target.x.runner='sh -c id'"),
            Some("--config")
        );
        assert_eq!(
            unsafe_scope_token("-p a --target-dir /tmp/x"),
            Some("--target-dir")
        );
        assert_eq!(
            unsafe_scope_token("--manifest-path /evil/Cargo.toml"),
            Some("--manifest-path")
        );
    }

    #[test]
    fn gate_category_classifies() {
        // lab-dependence wins over name.
        assert_eq!(
            gate_category("anchor_role_gates.sh", true),
            "lab-dependent (needs VMs)"
        );
        // curated security set + by-name security.
        assert_eq!(gate_category("secrets_hygiene_gates.sh", false), "security");
        assert_eq!(
            gate_category("check_backend_boundary_leakage.sh", false),
            "security"
        );
        assert_eq!(
            gate_category("role_auth_matrix_gates.sh", false),
            "security"
        );
        // role/platform, phase, release, other.
        assert_eq!(
            gate_category("anchor_role_gates.sh", false),
            "role / platform"
        );
        assert_eq!(gate_category("phase9_gates.sh", false), "phase");
        assert_eq!(
            gate_category("release_readiness_gates.sh", false),
            "release / readiness"
        );
        assert_eq!(gate_category("bootstrap_ci_tools.sh", false), "other");
    }

    #[test]
    fn script_needs_lab_detects_lab_refs() {
        assert!(script_needs_lab("#!/bin/bash\nutmctl list\n"));
        assert!(script_needs_lab(
            "run ops vm-lab-run-live-lab --inventory x"
        ));
        assert!(!script_needs_lab(
            "#!/bin/bash\ncargo test -p rustynet-policy\n"
        ));
    }

    #[test]
    fn security_gates_are_unique_and_nonempty() {
        assert!(!SECURITY_GATES.is_empty());
        let mut seen = std::collections::BTreeSet::new();
        for g in SECURITY_GATES {
            assert!(g.ends_with(".sh"), "{g} should be a .sh script");
            assert!(seen.insert(*g), "duplicate security gate {g}");
        }
    }
}
