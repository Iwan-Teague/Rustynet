//! Repo Context MCP Server — provides structured access to the Rustynet
//! documentation graph, requirements, security controls, and architecture rules.
//!
//! Tools:
//! - `get_read_order` — given a task, return the ordered docs to read
//! - `get_active_ledger` — given a topic, return the owning ledger + status
//! - `get_requirements` — return matching requirements
//! - `get_security_controls` — return matching security controls
//! - `get_architecture_constraints` — return non-negotiable constraints
//! - `get_definition_of_done` — return the DoD checklist
//! - `find_in_docs` — full-text search across all documentation
//! - `get_document` — read a specific document by path
//! - `get_crate_structure` — return workspace crate summary
//! - `get_orchestrator_stages` — return the orchestration stage list

#![forbid(unsafe_code)]

use rustynet_mcp::{
    McpServer, ServerInfo, Tool, ToolCallResult, json_schema_object, json_schema_string,
    run_server, text_content, tool_error, tool_success,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let server = RepoContextServer::new();
    run_server(server);
}

// ── Document index ────────────────────────────────────────────────────

struct DocEntry {
    path: &'static str,
    title: &'static str,
    description: &'static str,
    priority: u32, // lower = read first
    category: &'static str,
}

struct RepoContextServer {
    doc_index: Vec<DocEntry>,
    repo_root: PathBuf,
    topic_map: BTreeMap<&'static str, Vec<&'static str>>,
}

impl RepoContextServer {
    fn new() -> Self {
        // ── Canonical document index ────────────────────────────────
        let doc_index = vec![
            // Normative (read-first)
            DocEntry {
                path: "AGENTS.md",
                title: "Agent Operating Contract",
                description: "Mandatory execution guidance for AI agents. Mission, constraints, working style, definition of done.",
                priority: 1,
                category: "normative",
            },
            DocEntry {
                path: "CLAUDE.md",
                title: "CLAUDE.md (mirror of AGENTS.md)",
                description: "Mirror of AGENTS.md. Keep them aligned.",
                priority: 1,
                category: "normative",
            },
            DocEntry {
                path: "README.md",
                title: "README.md",
                description: "Project overview, quick start, live lab workflow, release readiness.",
                priority: 2,
                category: "normative",
            },
            DocEntry {
                path: "documents/README.md",
                title: "Documents Index",
                description: "Top-level map of the docs tree. Read order, normative docs, active ledgers, archives.",
                priority: 3,
                category: "normative",
            },
            DocEntry {
                path: "documents/Requirements.md",
                title: "Requirements (Brainstorm v0.3)",
                description: "Functional requirements, non-functional requirements, security requirements, architecture, roadmap, API sketches.",
                priority: 4,
                category: "normative",
            },
            DocEntry {
                path: "documents/SecurityMinimumBar.md",
                title: "Security Minimum Bar",
                description: "Non-negotiable security controls. Critical/High/Medium classifications. Bootstrap trust anchor, anchor node controls, role transition controls.",
                priority: 5,
                category: "normative",
            },
            // Active ledgers (primary execution)
            DocEntry {
                path: "documents/operations/active/RustynetDataplaneExecutionPlan_2026-05-18.md",
                title: "Dataplane Execution Plan (D2-D12)",
                description: "Source of truth for cross-network dataplane: gossip, relay, uPnP, IPv6, ICE, enrollment, anchor role, 6-role taxonomy.",
                priority: 6,
                category: "ledger",
            },
            DocEntry {
                path: "documents/operations/active/NodeRoleTaxonomy_2026-05-21.md",
                title: "Node Role Taxonomy (D12)",
                description: "Canonical taxonomy for 6 user-selectable roles: relay, anchor, exit, blind_exit, client, admin. Presets, transition matrix, platform eligibility.",
                priority: 6,
                category: "ledger",
            },
            DocEntry {
                path: "documents/operations/active/AnchorNodeRoleDesign_2026-05-21.md",
                title: "Anchor Node Role Design (D11)",
                description: "Canonical design for anchor role: definition, per-platform host capability, refactor inventory, security controls.",
                priority: 6,
                category: "ledger",
            },
            DocEntry {
                path: "documents/operations/active/MasterWorkPlan_2026-03-22.md",
                title: "Master Work Plan",
                description: "Repo-wide remaining work, cross-phase tracking.",
                priority: 6,
                category: "ledger",
            },
            DocEntry {
                path: "documents/operations/active/PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md",
                title: "Plug-and-Play Traversal Relay Delta Plan",
                description: "Defects driving D2/D3/D4. Traversal and relay readiness gaps.",
                priority: 6,
                category: "ledger",
            },
            DocEntry {
                path: "documents/operations/active/OpenWorkIndex_2026-04-17.md",
                title: "Open Work Index",
                description: "Cross-cuts all active work — what's open, what's blocked, what's in progress.",
                priority: 6,
                category: "ledger",
            },
            // Security
            DocEntry {
                path: "documents/operations/active/SecurityReview_2026-05-24.md",
                title: "Firm-Grade Security Review",
                description: "38 findings (RN-01..RN-38): 7 High, 9 Medium, 17 Low, 5 Info. CWE, file:line, exploit scenarios, P0/P1/P2 roadmap.",
                priority: 7,
                category: "security",
            },
            DocEntry {
                path: "documents/operations/active/SecurityHardeningBacklog_2026-06-01.md",
                title: "Security Hardening Backlog",
                description: "Actionable hardening TODO: net-new smoke/harness items + highest-priority open P0s re-verified on main.",
                priority: 7,
                category: "security",
            },
            DocEntry {
                path: "documents/operations/active/SecurityHardeningAudit_2026-04-28.md",
                title: "Security Hardening Audit",
                description: "Cross-platform security-hardening audit set.",
                priority: 7,
                category: "security",
            },
            // Operations & runbooks
            DocEntry {
                path: "documents/operations/README.md",
                title: "Operations Docs Index",
                description: "Runbook map, active work, evergreen references.",
                priority: 8,
                category: "operations",
            },
            DocEntry {
                path: "documents/operations/LiveLinuxLabOrchestrator.md",
                title: "Live Linux Lab Orchestrator",
                description: "How the live-lab orchestration works, stage descriptions, invocation.",
                priority: 8,
                category: "operations",
            },
            DocEntry {
                path: "documents/operations/ProductionRunbook.md",
                title: "Production Runbook",
                description: "Service and runtime operation guidance.",
                priority: 8,
                category: "operations",
            },
            DocEntry {
                path: "documents/operations/ReleaseReadinessGuardrails.md",
                title: "Release Readiness Guardrails",
                description: "Final release sign-off gate criteria.",
                priority: 8,
                category: "operations",
            },
        ];

        // ── Topic → relevant document paths ─────────────────────────
        let mut topic_map = BTreeMap::new();
        topic_map.insert(
            "traversal",
            vec![
                "documents/operations/active/PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md",
                "documents/operations/active/RustynetDataplaneExecutionPlan_2026-05-18.md",
                "documents/operations/active/UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md",
            ],
        );
        topic_map.insert(
            "relay",
            vec![
                "documents/operations/active/RustynetDataplaneExecutionPlan_2026-05-18.md",
                "documents/operations/active/PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md",
                "documents/operations/active/WindowsExitAndRelayDeltaPlan_2026-05-10.md",
            ],
        );
        topic_map.insert(
            "enrollment",
            vec![
                "documents/operations/active/RustynetDataplaneExecutionPlan_2026-05-18.md",
                "documents/SecurityMinimumBar.md",
            ],
        );
        topic_map.insert(
            "gossip",
            vec!["documents/operations/active/RustynetDataplaneExecutionPlan_2026-05-18.md"],
        );
        topic_map.insert(
            "anchor",
            vec![
                "documents/operations/active/AnchorNodeRoleDesign_2026-05-21.md",
                "documents/operations/active/NodeRoleTaxonomy_2026-05-21.md",
                "documents/SecurityMinimumBar.md",
            ],
        );
        topic_map.insert(
            "roles",
            vec![
                "documents/operations/active/NodeRoleTaxonomy_2026-05-21.md",
                "documents/SecurityMinimumBar.md",
            ],
        );
        topic_map.insert(
            "exit",
            vec![
                "documents/operations/active/WindowsExitAndRelayDeltaPlan_2026-05-10.md",
                "documents/operations/active/WindowsExitNodeRunbook_2026-06-04.md",
            ],
        );
        topic_map.insert(
            "windows",
            vec![
                "documents/operations/active/WindowsWorkingNodePlan_2026-04-17.md",
                "documents/operations/active/WindowsLiveLabReadinessPlan_2026-05-31.md",
                "documents/operations/active/WindowsExitAndRelayDeltaPlan_2026-05-10.md",
            ],
        );
        topic_map.insert(
            "macos",
            vec!["documents/operations/active/MacosUserspaceSharedBackendPlan_2026-05-08.md"],
        );
        topic_map.insert("orchestrator", vec!["documents/operations/active/RustNativeMultiPlatformOrchestratorPlan_2026-04-28.md", "documents/operations/active/OsAgnosticOrchestratorAndWindowsPeerDeltaPlan_2026-04-27.md"]);
        topic_map.insert(
            "security",
            vec![
                "documents/SecurityMinimumBar.md",
                "documents/operations/active/SecurityReview_2026-05-24.md",
                "documents/operations/active/SecurityHardeningBacklog_2026-06-01.md",
                "documents/operations/active/SecurityHardeningAudit_2026-04-28.md",
            ],
        );
        topic_map.insert(
            "killswitch",
            vec![
                "documents/SecurityMinimumBar.md",
                "documents/operations/active/SecurityHardeningBacklog_2026-06-01.md",
            ],
        );
        topic_map.insert(
            "dns",
            vec![
                "documents/Requirements.md",
                "documents/SecurityMinimumBar.md",
                "documents/operations/active/MagicDnsSignedZoneSchema_2026-03-09.md",
            ],
        );
        topic_map.insert(
            "testing",
            vec![
                "documents/Requirements.md",
                "documents/operations/active/TestCoverageImprovementPlan_2026-05-24.md",
            ],
        );
        topic_map.insert(
            "migration",
            vec![
                "documents/operations/active/ShellToRustMigrationPlan_2026-03-06.md",
                "documents/operations/active/StartShOperatorUxRustMigrationPlan_2026-05-24.md",
            ],
        );
        topic_map.insert(
            "vm",
            vec!["documents/operations/active/UTMVirtualMachineInventory_2026-03-31.md"],
        );
        topic_map.insert(
            "lab",
            vec![
                "documents/operations/active/UTMVirtualMachineInventory_2026-03-31.md",
                "documents/operations/LiveLinuxLabOrchestrator.md",
            ],
        );
        topic_map.insert(
            "dependencies",
            vec!["documents/operations/DependencyExceptionPolicy.md"],
        );
        topic_map.insert(
            "privacy",
            vec![
                "documents/SecurityMinimumBar.md",
                "documents/operations/PrivacyRetentionPolicy.md",
                "documents/operations/SecretRedactionCoverage.md",
            ],
        );

        Self {
            doc_index,
            repo_root: PathBuf::from("."),
            topic_map,
        }
    }

    fn find_doc(&self, path: &str) -> Option<&DocEntry> {
        self.doc_index.iter().find(|d| d.path == path)
    }

    fn read_file(&self, relative_path: &str) -> Result<String, String> {
        let full_path = self.repo_root.join(relative_path);
        fs::read_to_string(&full_path)
            .map_err(|e| format!("Cannot read '{}': {e}", full_path.display()))
    }
}

impl McpServer for RepoContextServer {
    fn server_info(&self) -> ServerInfo {
        ServerInfo {
            name: "rustynet-repo-context".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        }
    }

    fn tools(&self) -> Vec<Tool> {
        vec![
            Tool {
                name: "get_read_order".into(),
                description: "Given a task description, return the ordered list of documents to read before touching code, per the repo's precedence rules. Include requirements, security controls, and relevant active ledgers.".into(),
                input_schema: json_schema_object(
                    json!({"task": json_schema_string("Describe what you're about to work on (e.g., 'add a new relay feature', 'fix a Windows killswitch bug', 'implement enrollment token onboarding')")}),
                    vec!["task"],
                ),
            },
            Tool {
                name: "get_active_ledger".into(),
                description: "Given a topic keyword, return the active ledger document(s) that own it, with their status and cross-references.".into(),
                input_schema: json_schema_object(
                    json!({"topic": json_schema_string("Topic keyword: traversal, relay, enrollment, gossip, anchor, roles, exit, windows, macos, orchestrator, security, killswitch, dns, testing, migration, vm, lab, dependencies, privacy")}),
                    vec!["topic"],
                ),
            },
            Tool {
                name: "get_requirements".into(),
                description: "Return sections from Requirements.md matching a filter keyword.".into(),
                input_schema: json_schema_object(
                    json!({"filter": json_schema_string("Keyword to filter requirements: identity, enrollment, mesh, exit, lan, dns, acl, policy, security, architecture, testing, operations")}),
                    vec!["filter"],
                ),
            },
            Tool {
                name: "get_security_controls".into(),
                description: "Return security controls from SecurityMinimumBar.md matching a filter.".into(),
                input_schema: json_schema_object(
                    json!({"filter": json_schema_string("Keyword: critical, high, medium, crypto, tls, auth, keys, host, policy, web, leak, audit, supply, anchor, role, performance")}),
                    vec!["filter"],
                ),
            },
            Tool {
                name: "get_architecture_constraints".into(),
                description: "Return the non-negotiable engineering constraints from AGENTS.md §3 — Rust-first, no custom crypto, WireGuard-as-adapter, default-deny, fail-closed, one execution path, no TODO deferrals.".into(),
                input_schema: json_schema_object(json!({}), vec![]),
            },
            Tool {
                name: "get_definition_of_done".into(),
                description: "Return the Definition of Done checklist from AGENTS.md §9 — what must be true before work is complete (end-to-end impl, security bar, all gates pass, no TODOs, etc.).".into(),
                input_schema: json_schema_object(json!({}), vec![]),
            },
            Tool {
                name: "find_in_docs".into(),
                description: "Full-text search across the documentation tree for a query string. Returns matching documents with relevant excerpts.".into(),
                input_schema: json_schema_object(
                    json!({"query": json_schema_string("Search term or phrase")}),
                    vec!["query"],
                ),
            },
            Tool {
                name: "get_document".into(),
                description: "Read and return a specific document by its repo-relative path. Use the paths returned by get_read_order or get_active_ledger.".into(),
                input_schema: json_schema_object(
                    json!({"path": json_schema_string("Repo-relative path, e.g. 'documents/Requirements.md' or 'AGENTS.md'")}),
                    vec!["path"],
                ),
            },
            Tool {
                name: "get_crate_structure".into(),
                description: "Return a summary of the workspace crate structure — what each crate does, its dependencies, and its role in the architecture.".into(),
                input_schema: json_schema_object(json!({}), vec![]),
            },
            Tool {
                name: "get_orchestrator_stages".into(),
                description: "Return the list of orchestration stages with descriptions of what each stage does and which files implement it.".into(),
                input_schema: json_schema_object(json!({}), vec![]),
            },
            Tool {
                name: "get_security_findings".into(),
                description: "Query the firm-grade security review findings (RN-01 through RN-38) by status (open/fixed/accepted), severity (High/Medium/Low/Info), or specific finding ID. Returns CWE, file:line, exploit scenario, and remediation status.".into(),
                input_schema: json_schema_object(
                    json!({
                        "status": json_schema_string("Filter by status: open, fixed, accepted, or 'all' (default)"),
                        "severity": json_schema_string("Filter by severity: High, Medium, Low, Info, or 'all' (default)"),
                        "id": json_schema_string("Specific finding ID, e.g. 'RN-03' or 'RN-06'"),
                    }),
                    vec![],
                ),
            },
            Tool {
                name: "get_role_transition".into(),
                description: "Validate whether a role transition is allowed. Given from-role, to-role, and platform, returns whether the transition is allowed, blocked, requires owner signature, or is irreversible. Also returns required side-effects (service deploy/undeploy). Based on the canonical taxonomy in NodeRoleTaxonomy_2026-05-21.md.".into(),
                input_schema: json_schema_object(
                    json!({
                        "from": json_schema_string("Current role: relay, anchor, exit, blind_exit, client, admin"),
                        "to": json_schema_string("Target role: relay, anchor, exit, blind_exit, client, admin"),
                        "platform": json_schema_string("Target platform: linux, macos, windows, ios, android"),
                    }),
                    vec!["from", "to"],
                ),
            },
            Tool {
                name: "get_platform_support".into(),
                description: "Return the platform support matrix — which features and roles are supported on which OS. Includes current fail-closed restrictions (e.g., Windows exit requires live evidence before promotion). Based on the live PlatformSupportMatrix and current code state.".into(),
                input_schema: json_schema_object(
                    json!({
                        "feature": json_schema_string("Optional: filter by feature name (e.g., 'exit', 'relay', 'anchor', 'blind_exit', 'killswitch', 'wireguard-nt')"),
                        "platform": json_schema_string("Optional: filter by platform (linux, macos, windows, ios, android)"),
                    }),
                    vec![],
                ),
            },
        ]
    }

    fn call_tool(&self, name: &str, arguments: Option<Value>) -> ToolCallResult {
        match name {
            "get_read_order" => {
                let task = arguments
                    .and_then(|a| a.get("task").cloned())
                    .and_then(|v| v.as_str().map(String::from))
                    .unwrap_or_default();
                let task_lower = task.to_lowercase();

                let mut lines = Vec::new();
                lines.push(format!("# Document Read Order for: \"{task}\"\n"));

                // Always start with the mandatory pre-read docs
                lines.push("## Mandatory Pre-Read (always read these first)\n".into());
                for doc in &self.doc_index {
                    if doc.priority <= 5 {
                        lines.push(format!(
                            "{}. **{}** (`{}`) — {}",
                            doc.priority, doc.title, doc.path, doc.description
                        ));
                    }
                }

                // Find relevant topic-ledgers
                lines.push("\n## Relevant Active Ledgers\n".into());
                let mut found_ledgers = Vec::new();
                for (topic, paths) in &self.topic_map {
                    if task_lower.contains(&topic.to_lowercase()) {
                        for path in paths {
                            if let Some(doc) = self.find_doc(path) {
                                if !found_ledgers.iter().any(|(p, _)| p == &doc.path) {
                                    found_ledgers.push((doc.path, doc));
                                }
                            }
                        }
                    }
                }
                // Also add ledgers if the task is broad
                for doc in &self.doc_index {
                    if doc.category == "ledger"
                        && !found_ledgers.iter().any(|(p, _)| p == &doc.path)
                    {
                        found_ledgers.push((doc.path, doc));
                    }
                }
                found_ledgers.sort_by_key(|(_, d)| d.priority);
                for (i, (path, doc)) in found_ledgers.iter().enumerate() {
                    lines.push(format!(
                        "{}. **{}** (`{}`) — {}",
                        i + 1,
                        doc.title,
                        path,
                        doc.description
                    ));
                }

                // Add relevant runbooks
                lines.push("\n## Relevant Runbooks\n".into());
                let security_topics =
                    ["security", "killswitch", "anchor", "dns", "keys", "privacy"];
                let has_security = security_topics.iter().any(|t| task_lower.contains(t));
                if has_security || found_ledgers.is_empty() {
                    lines.push("- `documents/operations/README.md` — operations docs index (start here for runbooks)".into());
                    lines.push("- `documents/operations/ProductionRunbook.md` — service and runtime operation".into());
                    lines.push("- `documents/operations/ReleaseReadinessGuardrails.md` — release sign-off criteria".into());
                }
                if task_lower.contains("lab")
                    || task_lower.contains("vm")
                    || task_lower.contains("test")
                {
                    lines.push("- `documents/operations/LiveLinuxLabOrchestrator.md` — how the lab orchestration works".into());
                    lines.push("- `documents/operations/active/UTMVirtualMachineInventory_2026-03-31.md` — VM inventory + probe-and-recover runbook".into());
                }

                // Always mention gates
                lines.push("\n## Required Gates\n".into());
                lines.push(
                    "After making changes, run: `cargo run -p rustynet-xtask -- gates`".into(),
                );
                lines.push("Or individually: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo check --workspace --all-targets --all-features`, `cargo test --workspace --all-targets --all-features`".into());

                tool_success(&lines.join("\n"))
            }

            "get_active_ledger" => {
                let topic = arguments
                    .and_then(|a| a.get("topic").cloned())
                    .and_then(|v| v.as_str().map(String::from))
                    .unwrap_or_default();
                let topic_lower = topic.to_lowercase();

                let mut lines = vec![format!("# Active Ledgers for topic: \"{topic}\"\n")];

                if let Some(paths) = self.topic_map.get(topic_lower.as_str()) {
                    for path in paths {
                        if let Some(doc) = self.find_doc(path) {
                            lines.push(format!(
                                "- **{}** (`{}`) — {}",
                                doc.title, doc.path, doc.description
                            ));
                        } else {
                            // Try to read the file directly
                            match self.read_file(path) {
                                Ok(content) => {
                                    let title = content
                                        .lines()
                                        .next()
                                        .unwrap_or(path)
                                        .trim_start_matches("# ")
                                        .to_string();
                                    lines.push(format!(
                                        "- **{title}** (`{path}`) — (not in index, read directly)"
                                    ));
                                }
                                Err(e) => lines.push(format!("- `{path}` — {e}")),
                            }
                        }
                    }
                } else {
                    // Fuzzy search in doc_index
                    lines.push("No exact topic match. Searching document index...\n".into());
                    for doc in &self.doc_index {
                        let combined = format!("{} {} {}", doc.title, doc.description, doc.path)
                            .to_lowercase();
                        if combined.contains(&topic_lower) {
                            lines.push(format!(
                                "- **{}** (`{}`) — {}",
                                doc.title, doc.path, doc.description
                            ));
                        }
                    }
                    if lines.len() == 1 {
                        lines.push("No matching documents found. Try a different topic or use `find_in_docs`.".into());
                    }
                }

                tool_success(&lines.join("\n"))
            }

            "get_requirements" => {
                let filter = arguments
                    .and_then(|a| a.get("filter").cloned())
                    .and_then(|v| v.as_str().map(String::from))
                    .unwrap_or_default();
                let content = self
                    .read_file("documents/Requirements.md")
                    .unwrap_or_else(|e| format!("Error: {e}"));
                let filtered = filter_sections(&content, &filter, "## ");
                tool_success(&filtered)
            }

            "get_security_controls" => {
                let filter = arguments
                    .and_then(|a| a.get("filter").cloned())
                    .and_then(|v| v.as_str().map(String::from))
                    .unwrap_or_default();
                let content = self
                    .read_file("documents/SecurityMinimumBar.md")
                    .unwrap_or_else(|e| format!("Error: {e}"));
                let filtered = filter_sections(&content, &filter, "## ");
                tool_success(&filtered)
            }

            "get_architecture_constraints" => {
                let content = self
                    .read_file("AGENTS.md")
                    .unwrap_or_else(|e| format!("Error: {e}"));
                let section =
                    extract_section(&content, "## 3) Non-Negotiable Engineering Constraints");
                tool_success(&format!(
                    "# Non-Negotiable Engineering Constraints\n\n{section}"
                ))
            }

            "get_definition_of_done" => {
                let content = self
                    .read_file("AGENTS.md")
                    .unwrap_or_else(|e| format!("Error: {e}"));
                let section = extract_section(&content, "## 9) Definition of Done");
                tool_success(&format!("# Definition of Done\n\n{section}"))
            }

            "find_in_docs" => {
                let query = arguments
                    .and_then(|a| a.get("query").cloned())
                    .and_then(|v| v.as_str().map(String::from))
                    .unwrap_or_default();
                let query_lower = query.to_lowercase();

                let mut results = Vec::new();
                for doc in &self.doc_index {
                    if let Ok(content) = self.read_file(doc.path) {
                        if content.to_lowercase().contains(&query_lower) {
                            // Extract matching lines
                            let matches: Vec<String> = content
                                .lines()
                                .enumerate()
                                .filter(|(_, line)| line.to_lowercase().contains(&query_lower))
                                .take(5)
                                .map(|(i, line)| format!("  L{}: {}", i + 1, line.trim()))
                                .collect();
                            results.push(format!(
                                "## {} (`{}`)\n{}\n",
                                doc.title,
                                doc.path,
                                matches.join("\n")
                            ));
                        }
                    }
                }

                if results.is_empty() {
                    tool_success(&format!(
                        "No matches found for '{query}' in indexed documents."
                    ))
                } else {
                    tool_success(&format!(
                        "# Search results for: \"{query}\"\n\n{}",
                        results.join("\n")
                    ))
                }
            }

            "get_document" => {
                let path = arguments
                    .and_then(|a| a.get("path").cloned())
                    .and_then(|v| v.as_str().map(String::from))
                    .unwrap_or_default();

                // Security: prevent path traversal
                if path.contains("..") || path.starts_with('/') {
                    return tool_error("Invalid path: must be a repo-relative path without '..'");
                }

                match self.read_file(&path) {
                    Ok(content) => {
                        // Truncate very large files
                        let truncated = if content.lines().count() > 500 {
                            let head: String =
                                content.lines().take(500).collect::<Vec<_>>().join("\n");
                            format!(
                                "{head}\n\n... (truncated at 500 lines; {} total lines. Use a more specific tool for targeted reads.)",
                                content.lines().count()
                            )
                        } else {
                            content
                        };
                        tool_success(&truncated)
                    }
                    Err(e) => tool_error(&e),
                }
            }

            "get_crate_structure" => tool_success(CRATE_STRUCTURE),

            "get_orchestrator_stages" => tool_success(ORCHESTRATOR_STAGES),

            "get_security_findings" => {
                let status_filter = arguments
                    .as_ref()
                    .and_then(|a| a.get("status"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("all");
                let severity_filter = arguments
                    .as_ref()
                    .and_then(|a| a.get("severity"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("all");
                let id_filter = arguments
                    .as_ref()
                    .and_then(|a| a.get("id"))
                    .and_then(|v| v.as_str());

                let mut result = String::from("# Security Review Findings\n\n");

                for finding in SECURITY_FINDINGS {
                    if let Some(id) = id_filter {
                        if finding.id != id {
                            continue;
                        }
                    }
                    if status_filter != "all"
                        && finding.status.to_lowercase() != status_filter.to_lowercase()
                    {
                        continue;
                    }
                    if severity_filter != "all"
                        && finding.severity.to_lowercase() != severity_filter.to_lowercase()
                    {
                        continue;
                    }

                    result.push_str(&format!(
                        "## {} — {} ({})\n",
                        finding.id, finding.title, finding.severity
                    ));
                    result.push_str(&format!("- **Status:** {}\n", finding.status));
                    result.push_str(&format!("- **CWE:** {}\n", finding.cwe));
                    result.push_str(&format!("- **Location:** {}\n", finding.location));
                    result.push_str(&format!("- **Priority:** {}\n", finding.priority));
                    result.push_str(&format!("- **Description:** {}\n", finding.description));
                    if !finding.remediation.is_empty() {
                        result.push_str(&format!("- **Remediation:** {}\n", finding.remediation));
                    }
                    result.push('\n');
                }

                if result == "# Security Review Findings\n\n" {
                    result.push_str("No findings match the specified filters.\n");
                    result.push_str("Try broader filters or use 'all' for status and severity.\n");
                }

                tool_success(&result)
            }

            "get_role_transition" => {
                let from = arguments
                    .as_ref()
                    .and_then(|a| a.get("from"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let to = arguments
                    .as_ref()
                    .and_then(|a| a.get("to"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let platform = arguments
                    .as_ref()
                    .and_then(|a| a.get("platform"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("linux");

                if from.is_empty() || to.is_empty() {
                    return tool_error("Both 'from' and 'to' role parameters are required");
                }

                let result = validate_role_transition(from, to, platform);
                tool_success(&result)
            }

            "get_platform_support" => {
                let feature = arguments
                    .as_ref()
                    .and_then(|a| a.get("feature"))
                    .and_then(|v| v.as_str());
                let platform = arguments
                    .as_ref()
                    .and_then(|a| a.get("platform"))
                    .and_then(|v| v.as_str());

                let mut result = String::from("# Platform Support Matrix\n\n");
                result.push_str("Current as of 2026-06-06. Based on live code state.\n\n");

                for entry in PLATFORM_SUPPORT {
                    if let Some(f) = feature {
                        if !entry.feature.to_lowercase().contains(&f.to_lowercase()) {
                            continue;
                        }
                    }
                    if let Some(p) = platform {
                        if !entry.platform.to_lowercase().contains(&p.to_lowercase()) {
                            continue;
                        }
                    }

                    let status_icon = match entry.status {
                        "supported" => "✅",
                        "fail-closed" => "⛔",
                        "blocked" => "🚫",
                        "planned" => "📋",
                        "n/a" => "➖",
                        _ => "❓",
                    };
                    result.push_str(&format!(
                        "- {} **{}** on **{}**: {} ({})\n",
                        status_icon, entry.feature, entry.platform, entry.status, entry.note
                    ));
                }

                result.push_str("\n## Legend\n");
                result.push_str("- ✅ supported — end-to-end with live evidence\n");
                result.push_str("- ⛔ fail-closed — implemented but gated behind live evidence\n");
                result.push_str("- 🚫 blocked — platform limitation prevents implementation\n");
                result.push_str("- 📋 planned — on roadmap, not yet implemented\n");
                result.push_str("- ➖ n/a — not applicable to this platform\n");

                tool_success(&result)
            }

            _ => tool_error(&format!("Unknown tool: {name}")),
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────

fn filter_sections(content: &str, filter: &str, heading_prefix: &str) -> String {
    if filter.is_empty() {
        return content.to_string();
    }
    let filter_lower = filter.to_lowercase();
    let mut result = Vec::new();
    let mut current_section = Vec::new();
    let mut in_match = false;

    for line in content.lines() {
        if line.starts_with(heading_prefix) {
            // Flush previous section
            if in_match && !current_section.is_empty() {
                result.push(current_section.join("\n"));
                result.push(String::new());
            }
            current_section = vec![line.to_string()];
            in_match = line.to_lowercase().contains(&filter_lower);
        } else if in_match {
            current_section.push(line.to_string());
        }
    }
    // Flush last section
    if in_match && !current_section.is_empty() {
        result.push(current_section.join("\n"));
    }

    if result.is_empty() {
        format!("No sections matching '{filter}' found.")
    } else {
        result.join("\n")
    }
}

fn extract_section(content: &str, heading: &str) -> String {
    let mut lines = Vec::new();
    let mut capturing = false;
    for line in content.lines() {
        if line.trim() == heading {
            capturing = true;
            continue;
        }
        if capturing {
            if line.starts_with("## ") && !line.starts_with("### ") {
                break;
            }
            lines.push(line.to_string());
        }
    }
    lines.join("\n")
}

// ── Static reference data ─────────────────────────────────────────────

const CRATE_STRUCTURE: &str = r#"# Workspace Crate Structure

## Core / Domain (transport-agnostic)
- **`rustynet-control`** — Signed membership state, enrollment, gossip primitives, role presets. No transport knowledge.
- **`rustynet-policy`** — ACL and policy evaluation engine. Transport-agnostic.
- **`rustynet-crypto`** — Cryptographic primitives (signing, verification, key types). No custom crypto.
- **`rustynet-dns-zone`** — Magic DNS signed zone schema and validation.
- **`rustynet-local-security`** — Local security verification (runtime ACLs, key custody, service hardening).
- **`rustynet-sysinfo`** — System information gathering (host OS detection, interface enumeration).
- **`rustynet-operator`** — Operator UX, config management, wizards (migrating from shell).

## Backend Adapters (transport-specific)
- **`rustynet-backend-api`** — Backend trait definitions. What every backend must implement.
- **`rustynet-backend-wireguard`** — Production WireGuard backend (kernel + userspace).
- **`rustynet-backend-userspace`** — Userspace WireGuard backend (boringtun).
- **`rustynet-backend-stub`** — Stub backend for testing.

## Daemon & CLI
- **`rustynetd`** — The main daemon binary. WireGuard management, STUN, gossip, relay client, port mapping.
- **`rustynet-cli`** — CLI binary + VM lab orchestrator + live-lab wrappers. Largest crate.
- **`rustynet-relay`** — Production relay binary (frame forwarding between peers).

## Platform-Specific
- **`rustynet-windows-native`** — Windows-specific native code (WFP, named pipes, DPAPI).

## Tooling
- **`rustynet-xtask`** — Convenience runner for quality gates (fmt → check → clippy → test).
"#;

const ORCHESTRATOR_STAGES: &str = r#"# Live Lab Orchestration Stages

The orchestrator runs these stages in order. Each stage is an `OrchestrationStage` trait impl.

| # | Stage | What it does | File |
|---|-------|-------------|------|
| 1 | `preflight` | Local prerequisites (cargo, ssh, git) | `stage/preflight.rs` |
| 2 | `source_archive` | Tar the working tree → state archive | `stage/source_archive.rs` |
| 3 | `verify_ssh` | Confirm SSH reachability to each node | `stage/verify_ssh.rs` |
| 4 | `install` | scp source → cargo build → install daemon + service | `stage/install.rs` |
| 5 | `cleanup` | Wipe prior daemon state on each node | `stage/cleanup.rs` |
| 6 | `collect_pubkeys` | SSH each peer + read WireGuard public key | `stage/collect_pubkeys.rs` |
| 7 | `membership_init` | Exit node signs initial membership snapshot | `stage/membership_init.rs` |
| 8 | `distribute_membership` | scp membership snapshot to non-exit peers | `stage/distribute_membership.rs` |
| 9 | `distribute_assignments` | Exit signs + distributes assignments | `stage/distribute_assignments.rs` |
| 10 | `distribute_traversal` | Exit signs + distributes traversal hints | `stage/distribute_traversal.rs` |
| 11 | `distribute_dns_zone` | Exit signs + distributes DNS zone | `stage/distribute_dns_zone.rs` |
| 12 | `enforce_runtime` | Start daemon on each peer | `stage/enforce_runtime.rs` |
| 13 | `validate_runtime` | Each peer's daemon ingests state + validates | `stage/validate_runtime.rs` |
| 14 | `traffic_test_matrix` | Positive connectivity + default-deny negative tests | `stage/traffic_test_matrix.rs` |
| 15 | `role_switch_matrix` | Validate runtime role transitions | `stage/role_switch_matrix.rs` |
| 16 | `exit_handoff` | Validate exit-node handoff | `stage/exit_handoff.rs` |
| 17 | `active_exit` | Windows active-exit promotion (route advertise) | `stage/active_exit.rs` |
| 18 | `anchor_validation` | Anchor role validation (bundle-pull, gossip, enrollment) | `stage/anchor_validation.rs` |
| 19 | `relay_validation` | Relay role validation (relay colocation, frame forwarding) | `stage/relay_validation.rs` |
| 20 | `deploy_relay` | Deploy relay service on relay-capable nodes | `stage/deploy_relay.rs` |
| 21 | `final_cleanup` | Teardown + artifact collection | `stage/final_cleanup.rs` |

## Adapter Structure (per-OS impls)
- `adapter/node_adapter.rs` — `NodeAdapter` trait
- `adapter/linux.rs` + `linux_install.rs` + `linux_membership.rs` + `linux_traffic.rs`
- `adapter/windows.rs` + `windows_install.rs` + `windows_membership.rs` + `windows_traffic.rs`
- `adapter/macos.rs` + `macos_install.rs` + `macos_membership.rs` + `macos_traffic.rs`
- `adapter/ios.rs`, `adapter/android.rs` — stubs
- `adapter/factory.rs` — `node_adapter_for(platform, connection)` factory
- `adapter/ssh.rs` — SSH transport helpers
- `adapter/verifier_key.rs` — Verifier key installation

## VM Lab Entry Points (CLI)
- `ops vm-lab-discover-local-utm-summary` — discover VMs, quick summary
- `ops vm-lab-discover-local-utm` — discover VMs, full JSON
- `ops vm-lab-restart --all --wait-ready` — restart fleet, wait for SSH
- `ops vm-lab-setup-live-lab` — generate profile, run setup stages
- `ops vm-lab-run-live-lab` — run full live-lab suite
- `ops vm-lab-orchestrate-live-lab` — one-shot: discover → restart → setup → run → diagnose
- `ops vm-lab-diagnose-live-lab-failure` — collect failure context
"#;

// ── Below: data and helpers for new tools ──
// (appended by MCP server extension)

// ── Security findings data ──────────────────────────────────────────

struct SecurityFinding {
    id: &'static str,
    title: &'static str,
    severity: &'static str,
    status: &'static str,
    cwe: &'static str,
    location: &'static str,
    priority: &'static str,
    description: &'static str,
    remediation: &'static str,
}

static SECURITY_FINDINGS: &[SecurityFinding] = &[
    SecurityFinding {
        id: "RN-03", title: "force_fail_closed discarded — 10/44 sites",
        severity: "High", status: "open", cwe: "CWE-754",
        location: "crates/rustynetd/src/daemon.rs and 9 other files",
        priority: "P0",
        description: "The force_fail_closed safety mechanism was discarded at 10 of 44 call sites. When trust/security state is missing, invalid, or stale, these paths do not fail closed as required.",
        remediation: "Restore force_fail_closed at all 44 sites. Audit every path that reads trust state.",
    },
    SecurityFinding {
        id: "RN-04", title: "Pre-killswitch is opt-in and Linux-only",
        severity: "High", status: "open", cwe: "CWE-693",
        location: "crates/rustynetd/src/killswitch.rs",
        priority: "P0",
        description: "The pre-killswitch (applied before daemon starts) is opt-in via CLI flag and only on Linux (nftables). Windows/macOS have no pre-killswitch, creating a race window.",
        remediation: "Make pre-killswitch mandatory and cross-platform: WFP on Windows, pf anchor on macOS at install time.",
    },
    SecurityFinding {
        id: "RN-05", title: "Non-node: selectors bypass policy revocation",
        severity: "High", status: "open", cwe: "CWE-863",
        location: "crates/rustynet-policy/src/eval.rs",
        priority: "P0",
        description: "Policy selectors using non-'node:' prefixes can match after a node is revoked. Revocation only removes 'node:' selectors.",
        remediation: "Re-evaluate all selectors against current membership on every policy evaluation.",
    },
    SecurityFinding {
        id: "RN-06", title: "Windows killswitch allows IPv4 LAN egress",
        severity: "High", status: "open", cwe: "CWE-284",
        location: "crates/rustynetd/src/killswitch.rs (Windows netsh rules)",
        priority: "P0",
        description: "The Windows killswitch uses netsh rules allowing all IPv4 LAN egress. In protected mode this is a leak path.",
        remediation: "Move Windows egress policy to WFP for fine-grained control. Scope IPv4 LAN allowlist to known-safe CIDRs.",
    },
    SecurityFinding {
        id: "RN-07", title: "IPv6 leak in protected mode",
        severity: "High", status: "partial", cwe: "CWE-284",
        location: "crates/rustynetd/src/killswitch.rs",
        priority: "P0",
        description: "IPv6 traffic can bypass the killswitch. G8 partially remediates with apply/block/rollback but full leak-proof is deferred.",
        remediation: "Complete G8 IPv6 fail-closed: block all IPv6 at WFP/pf/nftables when protected mode active.",
    },
    SecurityFinding {
        id: "RN-11", title: "Empty membership/context = permissive default",
        severity: "High", status: "open", cwe: "CWE-276",
        location: "crates/rustynet-policy/src/eval.rs",
        priority: "P1",
        description: "When membership is empty or context missing, policy defaults to permissive. Violates default-deny requirement.",
        remediation: "Policy must deny by default when membership is empty. Add deny-on-empty guards.",
    },
    SecurityFinding {
        id: "RN-01", title: "Membership decoder DoS via unbounded allocation",
        severity: "High", status: "fixed", cwe: "CWE-770",
        location: "crates/rustynet-control/src/membership.rs",
        priority: "P0",
        description: "Unbounded allocation on attacker-controlled size fields. Fixed: added size caps (RL-1).",
        remediation: "",
    },
    SecurityFinding {
        id: "RN-14", title: "Unsafe code lint not enforced workspace-wide",
        severity: "Medium", status: "fixed", cwe: "CWE-242",
        location: "Cargo.toml workspace lints",
        priority: "P1",
        description: "unsafe_code=forbid now in workspace lints. Fixed (RL-2).",
        remediation: "",
    },
    SecurityFinding {
        id: "RN-22", title: "ed25519 verify_strict not used (malleability)",
        severity: "Medium", status: "fixed", cwe: "CWE-347",
        location: "crates/rustynet-crypto/src/verify.rs",
        priority: "P1",
        description: "Switched to verify_strict. Fixed (RL-3).",
        remediation: "",
    },
    SecurityFinding {
        id: "RN-24", title: "Secret material not zeroized after use",
        severity: "Medium", status: "fixed", cwe: "CWE-226",
        location: "Multiple files in rustynet-crypto, rustynetd",
        priority: "P1",
        description: "Added zeroize at all key material drop sites. Fixed (RL-4).",
        remediation: "",
    },
    SecurityFinding {
        id: "RN-21", title: "Fail-closed path accepted as operational risk",
        severity: "Low", status: "accepted", cwe: "N/A",
        location: "crates/rustynetd/src/daemon.rs",
        priority: "P2",
        description: "Daemon refuses to start without valid membership snapshot — intentional fail-closed. Accepted.",
        remediation: "",
    },
];

// ── Role transition validation ──────────────────────────────────────

fn validate_role_transition(from: &str, to: &str, platform: &str) -> String {
    let from_lower = from.to_lowercase();
    let to_lower = to.to_lowercase();
    let mut result = format!("# Role Transition: {from} → {to} on {platform}\n\n");

    if from_lower == to_lower {
        result.push_str("## Result: ✅ No-op (already in role)\n\n");
        return result;
    }

    let platform_blocks: &[(&str, &[&str])] = &[
        ("windows", &["exit", "blind_exit", "relay", "anchor"]),
        ("macos", &["blind_exit"]),
        ("ios", &["relay", "anchor", "exit", "blind_exit", "admin"]),
        ("android", &["relay", "anchor", "exit", "blind_exit", "admin"]),
    ];

    for (bp, br) in platform_blocks {
        if platform == *bp && br.contains(&to_lower.as_str()) {
            result.push_str("## Result: 🚫 Platform-Blocked\n\n");
            result.push_str(&format!("Role `{to}` is not supported on `{platform}`.\n"));
            result.push_str("The wizard greys out this role. `rustynet role set` returns `platform-blocked` error.\n");
            return result;
        }
    }

    if from_lower == "blind_exit" {
        result.push_str("## Result: 🚫 Irreversible\n\n");
        result.push_str("BlindExit is immutable. Requires factory-reset: wipe identity → re-enroll.\n");
        return result;
    }

    if to_lower == "blind_exit" {
        result.push_str("## Result: ⚠️ One-way (irreversible entry)\n\n");
        result.push_str("Entering BlindExit is permanent. Requires typed confirmation + --confirm-irreversible flag.\n\n");
    }

    let is_priv = |r: &str| matches!(r, "exit" | "relay" | "anchor" | "blind_exit");
    let adds = is_priv(&to_lower) && !is_priv(&from_lower);
    let removes = !is_priv(&to_lower) && is_priv(&from_lower);

    result.push_str("## Result: ✅ Allowed (requires owner signature)\n\n");
    result.push_str("Capability changes require an owner-signed membership bundle.\n\n");

    if to_lower == "relay" || adds && to_lower.contains("relay") {
        result.push_str("### Relay deploy:\n- Deploy rustynet-relay service BEFORE emitting signed bundle\n- Failure to deploy MUST abort transition\n\n");
    }
    if removes && from_lower.contains("relay") {
        result.push_str("### Relay undeploy:\n- Stop+remove rustynet-relay BEFORE revocation bundle\n- Failure to undeploy MUST keep previous state\n\n");
    }
    if to_lower == "exit" || to_lower.contains("exit") {
        result.push_str("### Exit setup:\n- Deploy forwarding+NAT before capability advertisement\n- On revocation: tear down NAT BEFORE removing capability\n- NAT residue after revocation = release-blocking defect\n\n");
    }
    if to_lower == "anchor" || to_lower.contains("anchor") {
        result.push_str("### Anchor setup:\n- Deploy enrollment endpoint (loopback bind by default)\n- Store HMAC secret in OS-secure custody\n- Token-gated bundle-pull + enrollment share single-use ledger\n- Port-mapping: lex-min node_id gets router lease\n\n");
    }
    result.push_str("### Audit: every transition emits append-only log entry (timestamp, from, to, side-effects, outcome, operator).\n");
    result
}

// ── Platform support data ───────────────────────────────────────────

struct PlatformSupportEntry {
    feature: &'static str,
    platform: &'static str,
    status: &'static str,
    note: &'static str,
}

static PLATFORM_SUPPORT: &[PlatformSupportEntry] = &[
    PlatformSupportEntry { feature: "client role", platform: "linux", status: "supported", note: "Full mesh client with WireGuard kernel backend" },
    PlatformSupportEntry { feature: "exit role", platform: "linux", status: "supported", note: "Full exit node with NAT/forwarding" },
    PlatformSupportEntry { feature: "relay role", platform: "linux", status: "supported", note: "Production relay binary, frame forwarding" },
    PlatformSupportEntry { feature: "anchor role", platform: "linux", status: "supported", note: "Bundle-pull, enrollment endpoint, port mapping authority" },
    PlatformSupportEntry { feature: "blind_exit role", platform: "linux", status: "supported", note: "Immutable blind exit with factory-reset requirement" },
    PlatformSupportEntry { feature: "killswitch", platform: "linux", status: "supported", note: "nftables pre-start and post-start" },
    PlatformSupportEntry { feature: "wireguard kernel", platform: "linux", status: "supported", note: "in-kernel wireguard.ko" },
    PlatformSupportEntry { feature: "uPnP/NAT-PMP/PCP", platform: "linux", status: "supported", note: "Gateway detection via /proc/net/route" },
    PlatformSupportEntry { feature: "IPv6 dataplane", platform: "linux", status: "supported", note: "Dual-stack with v6 candidate gathering" },
    PlatformSupportEntry { feature: "client role", platform: "macos", status: "supported", note: "Userspace WireGuard (boringtun)" },
    PlatformSupportEntry { feature: "exit role", platform: "macos", status: "fail-closed", note: "Implemented, gated behind live evidence (W5.4)" },
    PlatformSupportEntry { feature: "relay role", platform: "macos", status: "planned", note: "On roadmap, not yet implemented" },
    PlatformSupportEntry { feature: "anchor role", platform: "macos", status: "planned", note: "On roadmap, not yet implemented" },
    PlatformSupportEntry { feature: "blind_exit role", platform: "macos", status: "blocked", note: "Platform limitation" },
    PlatformSupportEntry { feature: "killswitch", platform: "macos", status: "fail-closed", note: "pf anchor available but pre-killswitch not mandatory" },
    PlatformSupportEntry { feature: "client role", platform: "windows", status: "supported", note: "WireGuard-NT, WFP killswitch, single-node smoke validated" },
    PlatformSupportEntry { feature: "exit role", platform: "windows", status: "fail-closed", note: "Implemented, gated behind WinNAT/HNS live evidence" },
    PlatformSupportEntry { feature: "relay role", platform: "windows", status: "planned", note: "D8 omitted (relay = Linux home server)" },
    PlatformSupportEntry { feature: "anchor role", platform: "windows", status: "planned", note: "On roadmap" },
    PlatformSupportEntry { feature: "blind_exit role", platform: "windows", status: "blocked", note: "Platform limitation" },
    PlatformSupportEntry { feature: "killswitch", platform: "windows", status: "partial", note: "netsh-based, IPv4 LAN egress allow-all (RN-06); WFP migration planned (E2)" },
    PlatformSupportEntry { feature: "wireguard-nt", platform: "windows", status: "supported", note: "WireGuard-NT kernel driver" },
    PlatformSupportEntry { feature: "DPAPI secrets", platform: "windows", status: "supported", note: "DPAPI-protected blobs under ProgramData\\RustyNet\\secrets" },
    PlatformSupportEntry { feature: "client role", platform: "ios", status: "planned", note: "Consumption-only; no hosting" },
    PlatformSupportEntry { feature: "client role", platform: "android", status: "planned", note: "Consumption-only; no hosting" },
    PlatformSupportEntry { feature: "all other roles", platform: "ios", status: "blocked", note: "Mobile is client-only by design" },
    PlatformSupportEntry { feature: "all other roles", platform: "android", status: "blocked", note: "Mobile is client-only by design" },
];
