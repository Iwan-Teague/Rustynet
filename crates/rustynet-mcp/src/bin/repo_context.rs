//! Repo Context MCP Server — structured access to the Rustynet documentation
//! graph, requirements, security controls, architecture rules, role taxonomy,
//! and platform support.
//!
//! Role-transition and platform-support answers are mirrored from the canonical
//! Rust implementations (cited inline) rather than hand-maintained tables, so
//! the two never contradict each other:
//! - transitions: `crates/rustynet-control/src/role_presets.rs::transition_plan`
//! - platform gate: `crates/rustynet-cli/src/vm_lab/orchestrator/role.rs`
//!   (`is_supported_for_platform`) + `rustynet-operator/src/role.rs`
//!   (`is_blind_exit_supported_host`)
//!
//! Security findings are parsed live from the SecurityReview §18 tracker, so
//! the full set is always reflected (never a stale curated subset).

#![forbid(unsafe_code)]

use rustynet_mcp::{
    GetPromptResult, McpServer, Prompt, PromptArgument, ReadResourceResult, Resource,
    ResourceContent, ServerInfo, Tool, ToolCallResult, json_schema_object, json_schema_string,
    prompt_text, read_file_capped, run_server, tool_error, tool_success, truncate_output,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let server = RepoContextServer::new();
    run_server(server);
}

const DOC_RESOURCE_SCHEME: &str = "rustynet-doc://";
const SECURITY_REVIEW_DOC: &str = "documents/operations/active/SecurityReview_2026-05-24.md";

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
        let doc_index = vec![
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
                description: "Functional, non-functional, security requirements, architecture, roadmap, API sketches.",
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
            DocEntry {
                path: SECURITY_REVIEW_DOC,
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
                SECURITY_REVIEW_DOC,
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
            repo_root: rustynet_mcp::repo_root(),
            topic_map,
        }
    }

    fn find_doc(&self, path: &str) -> Option<&DocEntry> {
        self.doc_index.iter().find(|d| d.path == path)
    }

    fn read_file(&self, relative_path: &str) -> Result<String, String> {
        // Cap reads so the full-tree search (find_in_docs/list_documents) can't be
        // blown up by a stray huge file committed under documents/.
        read_file_capped(&self.repo_root.join(relative_path), 8_000_000)
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
                description: "Given a task description, return the ordered list of documents to read before touching code, per the repo's precedence rules. Includes requirements, security controls, and relevant active ledgers.".into(),
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
                description: "Return the Definition of Done checklist from AGENTS.md §9.".into(),
                input_schema: json_schema_object(json!({}), vec![]),
            },
            Tool {
                name: "get_gate_definitions".into(),
                description: "Return the exact, authoritative quality-gate commands from AGENTS.md §7 (cargo fmt/clippy/check/test/audit/deny, the xtask fast runner, and scope-specific CI scripts). Use these verbatim before claiming work complete.".into(),
                input_schema: json_schema_object(json!({}), vec![]),
            },
            Tool {
                name: "find_in_docs".into(),
                description: "Full-text search across the ENTIRE documentation tree (every .md under documents/ plus the root AGENTS/CLAUDE/README) for a query string. Returns matching documents with file:line excerpts.".into(),
                input_schema: json_schema_object(
                    json!({"query": json_schema_string("Search term or phrase")}),
                    vec!["query"],
                ),
            },
            Tool {
                name: "list_documents".into(),
                description: "Enumerate every Markdown document in the repo (root normative docs + the full documents/ tree), grouped by directory, with each file's title and line count. Use this to discover docs that find_in_docs/get_active_ledger might not surface.".into(),
                input_schema: json_schema_object(
                    json!({"filter": json_schema_string("Optional: only list paths containing this substring (e.g. 'windows', 'operations/active')")}),
                    vec![],
                ),
            },
            Tool {
                name: "get_document".into(),
                description: "Read and return a specific document by its repo-relative path.".into(),
                input_schema: json_schema_object(
                    json!({"path": json_schema_string("Repo-relative path, e.g. 'documents/Requirements.md' or 'AGENTS.md'")}),
                    vec!["path"],
                ),
            },
            Tool {
                name: "get_crate_structure".into(),
                description: "Return a summary of the workspace crate structure — what each crate does, its architectural layer, and its boundary rule.".into(),
                input_schema: json_schema_object(json!({}), vec![]),
            },
            Tool {
                name: "which_crate".into(),
                description: "Given a repo-relative file path, return the owning crate, its architectural layer, what it does, and the boundary rule that governs it (e.g. domain crates must not import backend/WireGuard types). Use before editing to know the constraints.".into(),
                input_schema: json_schema_object(
                    json!({"path": json_schema_string("Repo-relative file path, e.g. 'crates/rustynet-policy/src/eval.rs'")}),
                    vec!["path"],
                ),
            },
            Tool {
                name: "get_orchestrator_stages".into(),
                description: "Return the list of orchestration stages with descriptions of what each stage does and which files implement it.".into(),
                input_schema: json_schema_object(json!({}), vec![]),
            },
            Tool {
                name: "get_security_findings".into(),
                description: "Query the security review findings (RN-01..RN-38), parsed live from the SecurityReview §18 master tracker, by status (open/fixed/accepted), severity (High/Medium/Low/Info), or specific finding ID. For a specific ID also returns the detailed finding block.".into(),
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
                description: "Validate whether a node role transition is allowed. Mirrors the canonical Rust validator (rustynet-control role_presets::transition_plan) and the platform gate. Returns kind (identity/local-only/signed/blocked/irreversible), capability deltas, service deploy/undeploy side-effects, and platform eligibility.".into(),
                input_schema: json_schema_object(
                    json!({
                        "from": json_schema_string("Current role: client, admin, exit, blind_exit, relay, anchor"),
                        "to": json_schema_string("Target role: client, admin, exit, blind_exit, relay, anchor"),
                        "platform": json_schema_string("Target platform: linux, macos, windows, ios, android"),
                    }),
                    vec!["from", "to"],
                ),
            },
            Tool {
                name: "get_platform_support".into(),
                description: "Return the platform support matrix — which roles and features are supported on which OS, mirrored from the live code gate (is_supported_for_platform + is_blind_exit_supported_host). Distinguishes supported / fail-closed (lab-assignable, pending live evidence) / planned / blocked.".into(),
                input_schema: json_schema_object(
                    json!({
                        "feature": json_schema_string("Optional: filter by role/feature name (e.g., 'exit', 'relay', 'anchor', 'blind_exit', 'killswitch')"),
                        "platform": json_schema_string("Optional: filter by platform (linux, macos, windows, ios, android)"),
                    }),
                    vec![],
                ),
            },
        ]
    }

    fn call_tool(&self, name: &str, arguments: Option<Value>) -> ToolCallResult {
        let args = arguments.as_ref();
        match name {
            "get_read_order" => self.get_read_order(arg_str(args, "task").unwrap_or_default()),
            "get_active_ledger" => {
                self.get_active_ledger(arg_str(args, "topic").unwrap_or_default())
            }
            "get_requirements" => {
                let filter = arg_str(args, "filter").unwrap_or_default();
                let content = self
                    .read_file("documents/Requirements.md")
                    .unwrap_or_else(|e| format!("Error: {e}"));
                tool_success(&filter_sections(&content, filter, "## "))
            }
            "get_security_controls" => {
                let filter = arg_str(args, "filter").unwrap_or_default();
                let content = self
                    .read_file("documents/SecurityMinimumBar.md")
                    .unwrap_or_else(|e| format!("Error: {e}"));
                tool_success(&filter_sections(&content, filter, "## "))
            }
            "get_architecture_constraints" => match self.read_file("AGENTS.md") {
                Ok(content) => tool_success(&format!(
                    "# Non-Negotiable Engineering Constraints\n\n{}",
                    extract_section(&content, "## 3) Non-Negotiable Engineering Constraints")
                )),
                Err(e) => tool_error(&e),
            },
            "get_definition_of_done" => match self.read_file("AGENTS.md") {
                Ok(content) => tool_success(&format!(
                    "# Definition of Done\n\n{}",
                    extract_section(&content, "## 9) Definition of Done")
                )),
                Err(e) => tool_error(&e),
            },
            "get_gate_definitions" => match self.read_file("AGENTS.md") {
                Ok(content) => {
                    let section = extract_section(&content, "## 7) Validation and CI Gates");
                    tool_success(&format!(
                        "# Quality Gates (authoritative, from AGENTS.md §7)\n\n{section}\n\n\
                         ## Architecture boundary gate\n- `./scripts/ci/check_backend_boundary_leakage.sh` \
                         — domain crates must not import backend/WireGuard types.\n\n\
                         Use the gate-runner MCP server (run_gates / run_fmt / run_clippy / run_check / \
                         run_test / run_security_audit / run_gate_script) to execute these."
                    ))
                }
                Err(e) => tool_error(&e),
            },
            "find_in_docs" => self.find_in_docs(arg_str(args, "query").unwrap_or_default()),
            "list_documents" => self.list_documents(arg_str(args, "filter")),
            "get_document" => self.get_document(arg_str(args, "path").unwrap_or_default()),
            "get_crate_structure" => tool_success(&render_crate_structure()),
            "which_crate" => tool_success(&which_crate(arg_str(args, "path").unwrap_or_default())),
            "get_orchestrator_stages" => tool_success(ORCHESTRATOR_STAGES),
            "get_security_findings" => self.get_security_findings(
                arg_str(args, "status").unwrap_or("all"),
                arg_str(args, "severity").unwrap_or("all"),
                arg_str(args, "id"),
            ),
            "get_role_transition" => {
                let from = arg_str(args, "from").unwrap_or("");
                let to = arg_str(args, "to").unwrap_or("");
                let platform = arg_str(args, "platform").unwrap_or("linux");
                if from.is_empty() || to.is_empty() {
                    return tool_error("Both 'from' and 'to' role parameters are required");
                }
                match describe_role_transition(from, to, platform) {
                    Ok(s) => tool_success(&s),
                    Err(e) => tool_error(&e),
                }
            }
            "get_platform_support" => tool_success(&render_platform_support(
                arg_str(args, "feature"),
                arg_str(args, "platform"),
            )),
            _ => tool_error(&format!("Unknown tool: {name}")),
        }
    }

    // ── Resources: expose the curated doc index over MCP resources/* ──
    fn resources(&self) -> Vec<Resource> {
        self.doc_index
            .iter()
            .map(|d| Resource {
                uri: format!("{DOC_RESOURCE_SCHEME}{}", d.path),
                name: d.title.to_string(),
                description: Some(d.description.to_string()),
                mime_type: Some("text/markdown".to_string()),
            })
            .collect()
    }

    fn read_resource(&self, uri: &str) -> Option<ReadResourceResult> {
        let rel = uri.strip_prefix(DOC_RESOURCE_SCHEME)?;
        // Reuse the path-safety checks in get_document's resolver.
        let content = self.read_safe(rel).ok()?;
        Some(ReadResourceResult {
            contents: vec![ResourceContent {
                uri: uri.to_string(),
                mime_type: Some("text/markdown".to_string()),
                text: Some(content),
            }],
        })
    }

    // ── Prompts: inject scoped-task guidance / role-transition analysis ──
    fn prompts(&self) -> Vec<Prompt> {
        vec![
            Prompt {
                name: "scoped-task".into(),
                description: Some(
                    "Assemble the read-order, architecture constraints, gates and Definition of Done for a task before you start.".into(),
                ),
                arguments: vec![PromptArgument {
                    name: "task".into(),
                    description: Some("What you're about to work on".into()),
                    required: Some(true),
                }],
            },
            Prompt {
                name: "role-transition-plan".into(),
                description: Some(
                    "Produce the validated plan for a node role transition (kind, side-effects, platform gate).".into(),
                ),
                arguments: vec![
                    PromptArgument {
                        name: "from".into(),
                        description: Some("Current role".into()),
                        required: Some(true),
                    },
                    PromptArgument {
                        name: "to".into(),
                        description: Some("Target role".into()),
                        required: Some(true),
                    },
                    PromptArgument {
                        name: "platform".into(),
                        description: Some("Target platform (default linux)".into()),
                        required: Some(false),
                    },
                ],
            },
        ]
    }

    fn get_prompt(&self, name: &str, arguments: Option<Value>) -> Option<GetPromptResult> {
        let args = arguments.as_ref();
        match name {
            "scoped-task" => {
                let task = arg_str(args, "task").unwrap_or_default();
                let read_order = self
                    .get_read_order(task)
                    .content
                    .first()
                    .map(|c| c.text.clone())
                    .unwrap_or_default();
                let constraints = self
                    .read_file("AGENTS.md")
                    .map(|c| extract_section(&c, "## 3) Non-Negotiable Engineering Constraints"))
                    .unwrap_or_default();
                let dod = self
                    .read_file("AGENTS.md")
                    .map(|c| extract_section(&c, "## 9) Definition of Done"))
                    .unwrap_or_default();
                let body = format!(
                    "You are about to work on: \"{task}\".\n\nFollow the repo operating contract.\n\n\
                     {read_order}\n\n# Non-Negotiable Constraints\n{constraints}\n\n\
                     # Definition of Done\n{dod}\n"
                );
                Some(prompt_text("Scoped task briefing", body))
            }
            "role-transition-plan" => {
                let from = arg_str(args, "from").unwrap_or("");
                let to = arg_str(args, "to").unwrap_or("");
                let platform = arg_str(args, "platform").unwrap_or("linux");
                let body = describe_role_transition(from, to, platform)
                    .unwrap_or_else(|e| format!("Error: {e}"));
                Some(prompt_text("Role transition plan", body))
            }
            _ => None,
        }
    }
}

// ── Tool implementations ──────────────────────────────────────────────

impl RepoContextServer {
    fn get_read_order(&self, task: &str) -> ToolCallResult {
        let task_lower = task.to_lowercase();
        let mut lines = vec![format!("# Document Read Order for: \"{task}\"\n")];

        lines.push("## Mandatory Pre-Read (always read these first)\n".into());
        for doc in &self.doc_index {
            if doc.priority <= 5 {
                lines.push(format!(
                    "{}. **{}** (`{}`) — {}",
                    doc.priority, doc.title, doc.path, doc.description
                ));
            }
        }

        lines.push("\n## Relevant Active Ledgers\n".into());
        let mut found: Vec<&DocEntry> = Vec::new();
        for (topic, paths) in &self.topic_map {
            if task_lower.contains(&topic.to_lowercase()) {
                for path in paths {
                    if let Some(doc) = self.find_doc(path)
                        && !found.iter().any(|d| d.path == doc.path)
                    {
                        found.push(doc);
                    }
                }
            }
        }
        // Only fall back to listing every ledger when nothing matched the task
        // (broad/unknown task). Otherwise keep the list focused.
        if found.is_empty() {
            for doc in &self.doc_index {
                if doc.category == "ledger" {
                    found.push(doc);
                }
            }
        }
        found.sort_by_key(|d| d.priority);
        for (i, doc) in found.iter().enumerate() {
            lines.push(format!(
                "{}. **{}** (`{}`) — {}",
                i + 1,
                doc.title,
                doc.path,
                doc.description
            ));
        }

        let security_topics = ["security", "killswitch", "anchor", "dns", "keys", "privacy"];
        if security_topics.iter().any(|t| task_lower.contains(t)) {
            lines.push("\n## Relevant Runbooks\n".into());
            lines.push("- `documents/operations/README.md` — operations docs index".into());
            lines.push(
                "- `documents/operations/ProductionRunbook.md` — service and runtime operation"
                    .into(),
            );
            lines.push("- `documents/operations/ReleaseReadinessGuardrails.md` — release sign-off criteria".into());
        }
        if task_lower.contains("lab") || task_lower.contains("vm") || task_lower.contains("test") {
            lines.push("\n## Lab Runbooks\n".into());
            lines.push("- `documents/operations/LiveLinuxLabOrchestrator.md` — how the lab orchestration works".into());
            lines.push("- `documents/operations/active/UTMVirtualMachineInventory_2026-03-31.md` — VM inventory + probe-and-recover".into());
        }

        lines.push("\n## Required Gates\n".into());
        lines.push("After changes run: `cargo run -p rustynet-xtask -- gates` (or use get_gate_definitions for the full list).".into());

        tool_success(&lines.join("\n"))
    }

    fn get_active_ledger(&self, topic: &str) -> ToolCallResult {
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
            lines.push("No exact topic match. Searching document index...\n".into());
            for doc in &self.doc_index {
                let combined =
                    format!("{} {} {}", doc.title, doc.description, doc.path).to_lowercase();
                if combined.contains(&topic_lower) {
                    lines.push(format!(
                        "- **{}** (`{}`) — {}",
                        doc.title, doc.path, doc.description
                    ));
                }
            }
            if lines.len() == 2 {
                lines.push(
                    "No matching documents found. Try a different topic or use `find_in_docs`."
                        .into(),
                );
            }
        }
        tool_success(&lines.join("\n"))
    }

    fn find_in_docs(&self, query: &str) -> ToolCallResult {
        if query.trim().is_empty() {
            return tool_error("Missing required parameter: query");
        }
        let query_lower = query.to_lowercase();
        let files = self.all_doc_paths();
        let mut results = Vec::new();
        let mut files_with_matches = 0;

        for rel in &files {
            if files_with_matches >= 60 {
                results.push(format!(
                    "\n... (stopped after {files_with_matches} matching files; narrow the query)"
                ));
                break;
            }
            let Ok(content) = self.read_file(rel) else {
                continue;
            };
            if !content.to_lowercase().contains(&query_lower) {
                continue;
            }
            let matches: Vec<String> = content
                .lines()
                .enumerate()
                .filter(|(_, line)| line.to_lowercase().contains(&query_lower))
                .take(5)
                .map(|(i, line)| format!("  L{}: {}", i + 1, line.trim()))
                .collect();
            results.push(format!("## `{rel}`\n{}\n", matches.join("\n")));
            files_with_matches += 1;
        }

        if files_with_matches == 0 {
            tool_success(&format!(
                "No matches found for '{query}' across {} documents.",
                files.len()
            ))
        } else {
            tool_success(&truncate_output(
                &format!(
                    "# Search results for \"{query}\" ({files_with_matches} files)\n\n{}",
                    results.join("\n")
                ),
                800,
                80_000,
            ))
        }
    }

    fn list_documents(&self, filter: Option<&str>) -> ToolCallResult {
        let files = self.all_doc_paths();
        let filter_lower = filter.map(|f| f.to_lowercase());
        let mut by_dir: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut count = 0;

        for rel in &files {
            if let Some(f) = &filter_lower
                && !rel.to_lowercase().contains(f)
            {
                continue;
            }
            let (title, line_count) = match self.read_file(rel) {
                Ok(c) => {
                    let title = c
                        .lines()
                        .find(|l| l.starts_with("# "))
                        .map(|l| l.trim_start_matches("# ").trim().to_string())
                        .unwrap_or_else(|| "(no title)".into());
                    (title, c.lines().count())
                }
                Err(_) => ("(unreadable)".into(), 0),
            };
            let dir = Path::new(rel)
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "(root)".into());
            let file = Path::new(rel)
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| rel.clone());
            by_dir
                .entry(dir)
                .or_default()
                .push(format!("- `{file}` — {title} ({line_count} lines)"));
            count += 1;
        }

        let mut out = format!("# Documents ({count} files)\n");
        for (dir, items) in &by_dir {
            out.push_str(&format!("\n## {dir}/\n"));
            for item in items {
                out.push_str(item);
                out.push('\n');
            }
        }
        tool_success(&truncate_output(&out, 1000, 80_000))
    }

    fn get_document(&self, path: &str) -> ToolCallResult {
        match self.read_safe(path) {
            Ok(content) => tool_success(&truncate_output(&content, 600, 80_000)),
            Err(e) => tool_error(&e),
        }
    }

    fn get_security_findings(
        &self,
        status_filter: &str,
        severity_filter: &str,
        id_filter: Option<&str>,
    ) -> ToolCallResult {
        let content = match self.read_file(SECURITY_REVIEW_DOC) {
            Ok(c) => c,
            Err(e) => {
                return tool_error(&format!(
                    "Cannot read security review (failing closed): {e}"
                ));
            }
        };
        let findings = parse_findings_table(&content);
        if findings.is_empty() {
            return tool_error(
                "Could not parse the §18 master finding tracker — doc format may have changed.",
            );
        }

        let mut out = format!(
            "# Security Review Findings\n\n_Parsed live from `{SECURITY_REVIEW_DOC}` §18 — {} findings total._\n\n",
            findings.len()
        );
        let mut shown = 0;
        for f in &findings {
            if let Some(id) = id_filter
                && !f.id.eq_ignore_ascii_case(id)
            {
                continue;
            }
            if status_filter != "all" && !f.status.eq_ignore_ascii_case(status_filter) {
                continue;
            }
            if severity_filter != "all" && !severity_matches(&f.severity, severity_filter) {
                continue;
            }
            out.push_str(&format!(
                "- **{}** — {} · {} · status: **{}** · ref: {}\n",
                f.id, f.severity, f.domain, f.status, f.reference
            ));
            // For a specific ID, append the detailed finding block if present.
            if id_filter.is_some()
                && let Some(block) = extract_finding_block(&content, &f.id)
            {
                out.push_str(&format!("\n{block}\n"));
            }
            shown += 1;
        }

        if shown == 0 {
            out.push_str("\nNo findings match the specified filters.\n");
        } else {
            out.push_str(&format!("\n_{shown} finding(s) shown._\n"));
        }
        tool_success(&truncate_output(&out, 600, 80_000))
    }

    // ── Path-safe document read (shared by get_document + resources) ──
    fn read_safe(&self, path: &str) -> Result<String, String> {
        if path.contains("..") || path.starts_with('/') {
            return Err("Invalid path: must be a repo-relative path without '..'".into());
        }
        let full = self.repo_root.join(path);
        let canon = full
            .canonicalize()
            .map_err(|e| format!("Cannot read '{path}': {e}"))?;
        let root_canon = self
            .repo_root
            .canonicalize()
            .map_err(|e| format!("Cannot resolve repo root: {e}"))?;
        if !canon.starts_with(&root_canon) {
            return Err("Invalid path: escapes the repository root".into());
        }
        fs::read_to_string(&canon).map_err(|e| format!("Cannot read '{path}': {e}"))
    }

    /// Every Markdown document: the root normative docs + the full
    /// `documents/` tree (recursive). Returns repo-relative paths, sorted.
    fn all_doc_paths(&self) -> Vec<String> {
        let mut out = Vec::new();
        for root_doc in ["AGENTS.md", "CLAUDE.md", "README.md"] {
            if self.repo_root.join(root_doc).is_file() {
                out.push(root_doc.to_string());
            }
        }
        collect_md(&self.repo_root.join("documents"), &self.repo_root, &mut out);
        out.sort();
        out.dedup();
        out
    }
}

// ── Free helpers ──────────────────────────────────────────────────────

fn arg_str<'a>(args: Option<&'a Value>, key: &str) -> Option<&'a str> {
    args.and_then(|a| a.get(key)).and_then(|v| v.as_str())
}

/// Recursively collect `*.md` files under `dir`, pushing repo-relative paths.
fn collect_md(dir: &Path, repo_root: &Path, out: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') {
            continue;
        }
        if path.is_dir() {
            collect_md(&path, repo_root, out);
        } else if path.extension().is_some_and(|e| e == "md")
            && let Ok(rel) = path.strip_prefix(repo_root)
        {
            out.push(rel.to_string_lossy().to_string());
        }
    }
}

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
    lines.join("\n").trim().to_string()
}

// ── Security findings parsing (source of truth: SecurityReview §18) ────

struct Finding {
    id: String,
    severity: String,
    domain: String,
    status: String,
    reference: String,
}

fn normalize_status(raw: &str) -> String {
    let lower = raw.to_lowercase();
    if lower.contains("fixed") {
        "Fixed".into()
    } else if lower.contains("accepted") {
        "Accepted".into()
    } else if lower.contains("open") {
        "Open".into()
    } else {
        // Strip markdown emphasis, take the first token.
        raw.replace('*', "")
            .split_whitespace()
            .next()
            .unwrap_or("Open")
            .to_string()
    }
}

fn normalize_severity(raw: &str) -> String {
    match raw.to_lowercase().as_str() {
        "high" => "High".into(),
        "med" | "medium" => "Medium".into(),
        "low" => "Low".into(),
        "info" | "informational" => "Info".into(),
        other => other.to_string(),
    }
}

fn severity_matches(finding_sev: &str, filter: &str) -> bool {
    normalize_severity(finding_sev).eq_ignore_ascii_case(&normalize_severity(filter))
}

/// Parse the `| ID | Sev | Domain | Status | Ref |` table under
/// "## 18. Master finding-status tracker". Expands ranges like `RN-34–38`.
fn parse_findings_table(content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut in_section = false;
    for line in content.lines() {
        if line.trim_start().starts_with("## 18.") {
            in_section = true;
            continue;
        }
        if in_section && line.starts_with("## ") {
            break; // next section
        }
        if !in_section {
            continue;
        }
        let trimmed = line.trim();
        if !trimmed.starts_with("| RN") {
            continue;
        }
        let cells: Vec<String> = trimmed
            .split('|')
            .map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty())
            .collect();
        // Expect: [ID, Sev, Domain, Status, Ref]
        if cells.len() < 4 {
            continue;
        }
        let id_cell = &cells[0];
        let severity = normalize_severity(&cells[1]);
        let domain = cells[2].clone();
        let status = normalize_status(&cells[3]);
        let reference = cells.get(4).cloned().unwrap_or_default();

        for id in expand_finding_ids(id_cell) {
            out.push(Finding {
                id,
                severity: severity.clone(),
                domain: domain.clone(),
                status: status.clone(),
                reference: reference.clone(),
            });
        }
    }
    out
}

/// Expand an ID cell into concrete IDs. `RN-34–38` → RN-34..=RN-38.
fn expand_finding_ids(cell: &str) -> Vec<String> {
    let rest = match cell.strip_prefix("RN-") {
        Some(r) => r,
        None => return vec![cell.to_string()],
    };
    // Range separators: en-dash or hyphen.
    let parts: Vec<&str> = rest.split(['–', '-']).collect();
    if parts.len() == 2
        && let (Ok(start), Ok(end)) = (
            parts[0].trim().parse::<u32>(),
            parts[1].trim().parse::<u32>(),
        )
        && start <= end
        && end - start < 100
    {
        return (start..=end).map(|n| format!("RN-{n:02}")).collect();
    }
    vec![cell.to_string()]
}

/// Extract the detailed `### RN-NN …` block for a finding, if present.
fn extract_finding_block(content: &str, id: &str) -> Option<String> {
    let needle = format!("### {id} ");
    let needle_exact = format!("### {id}\n");
    let mut lines = Vec::new();
    let mut capturing = false;
    for line in content.lines() {
        if line.starts_with(&needle) || line == needle_exact.trim_end() {
            capturing = true;
            lines.push(line.to_string());
            continue;
        }
        if capturing {
            if line.starts_with("### ") || line.starts_with("## ") {
                break;
            }
            lines.push(line.to_string());
        }
    }
    if capturing {
        Some(lines.join("\n").trim().to_string())
    } else {
        None
    }
}

// ── Role taxonomy mirror ──────────────────────────────────────────────
// Source of truth: crates/rustynet-control/src/role_presets.rs
// (RolePreset, ROLE_PRESET_TABLE, transition_plan). Kept in sync via tests.

#[derive(Clone, Copy, PartialEq, Eq)]
enum Preset {
    Client,
    Admin,
    Exit,
    BlindExit,
    Relay,
    Anchor,
}

impl Preset {
    fn parse(s: &str) -> Option<Preset> {
        match s.to_lowercase().as_str() {
            "client" => Some(Preset::Client),
            "admin" => Some(Preset::Admin),
            "exit" => Some(Preset::Exit),
            "blind_exit" | "blindexit" => Some(Preset::BlindExit),
            "relay" => Some(Preset::Relay),
            "anchor" => Some(Preset::Anchor),
            _ => None,
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            Preset::Client => "client",
            Preset::Admin => "admin",
            Preset::Exit => "exit",
            Preset::BlindExit => "blind_exit",
            Preset::Relay => "relay",
            Preset::Anchor => "anchor",
        }
    }
    /// Axis-1 primary role (Client | Admin | BlindExit).
    fn primary(self) -> &'static str {
        match self {
            Preset::Client => "client",
            Preset::BlindExit => "blind_exit",
            _ => "admin",
        }
    }
    /// Axis-2 capabilities (mirror of ROLE_PRESET_TABLE).
    fn capabilities(self) -> &'static [&'static str] {
        match self {
            Preset::Client | Preset::Admin => &[],
            Preset::Exit | Preset::BlindExit => &["serves_exit"],
            Preset::Relay => &["serves_relay"],
            Preset::Anchor => &[
                "anchor.gossip_seed",
                "anchor.bundle_pull",
                "anchor.enrollment_endpoint",
                "anchor.relay_colocation",
                "anchor.port_mapping_authoritative",
            ],
        }
    }
}

fn needs_relay_binary(caps: &[&str]) -> bool {
    caps.iter()
        .any(|c| *c == "serves_relay" || *c == "anchor.relay_colocation")
}

#[derive(PartialEq, Eq, Debug)]
enum TransitionKind {
    Identity,
    LocalOnly,
    SignedMembership,
    Blocked,
    Irreversible,
}

struct TransitionPlan {
    kind: TransitionKind,
    reason: &'static str,
    adds: Vec<&'static str>,
    removes: Vec<&'static str>,
    relay_deploy: bool,
    relay_undeploy: bool,
    primary_change: Option<(&'static str, &'static str)>,
}

/// Faithful mirror of `role_presets::transition_plan`.
fn plan_transition(from: Preset, to: Preset) -> TransitionPlan {
    if from == to {
        return TransitionPlan {
            kind: TransitionKind::Identity,
            reason: "from == to; no-op",
            adds: vec![],
            removes: vec![],
            relay_deploy: false,
            relay_undeploy: false,
            primary_change: None,
        };
    }
    if from == Preset::BlindExit {
        return TransitionPlan {
            kind: TransitionKind::Blocked,
            reason: "blind_exit is immutable; factory reset + fresh key provisioning required to change role",
            adds: vec![],
            removes: vec![],
            relay_deploy: false,
            relay_undeploy: false,
            primary_change: None,
        };
    }

    let from_caps = from.capabilities();
    let to_caps = to.capabilities();
    let adds: Vec<&'static str> = to_caps
        .iter()
        .filter(|c| !from_caps.contains(c))
        .copied()
        .collect();
    let removes: Vec<&'static str> = from_caps
        .iter()
        .filter(|c| !to_caps.contains(c))
        .copied()
        .collect();
    let relay_deploy = !needs_relay_binary(from_caps) && needs_relay_binary(to_caps);
    let relay_undeploy = needs_relay_binary(from_caps) && !needs_relay_binary(to_caps);
    let primary_change = if from.primary() != to.primary() {
        Some((from.primary(), to.primary()))
    } else {
        None
    };

    let (kind, reason) = if to == Preset::BlindExit {
        (
            TransitionKind::Irreversible,
            "becoming blind_exit wipes node identity and re-enrolls fresh; this cannot be undone without another factory reset",
        )
    } else if !adds.is_empty() || !removes.is_empty() {
        (
            TransitionKind::SignedMembership,
            "capability set changes; requires an owner-signed membership update record",
        )
    } else if primary_change.is_some() {
        (
            TransitionKind::LocalOnly,
            "primary role changes (admin ↔ client); local config write + daemon reload, no signed bundle",
        )
    } else {
        (TransitionKind::Identity, "no change")
    };

    TransitionPlan {
        kind,
        reason,
        adds,
        removes,
        relay_deploy,
        relay_undeploy,
        primary_change,
    }
}

fn describe_role_transition(from: &str, to: &str, platform: &str) -> Result<String, String> {
    let from_p = Preset::parse(from).ok_or_else(|| {
        format!("Unknown 'from' role: {from} (use client/admin/exit/blind_exit/relay/anchor)")
    })?;
    let to_p = Preset::parse(to).ok_or_else(|| {
        format!("Unknown 'to' role: {to} (use client/admin/exit/blind_exit/relay/anchor)")
    })?;

    let mut out = format!("# Role Transition: {from} → {to} on {platform}\n\n");

    // Platform gate on the destination role.
    let support = role_support(to_p, platform);
    out.push_str("## Platform eligibility\n");
    match support {
        Support::Supported => {
            out.push_str(&format!("- ✅ `{to}` is supported on `{platform}`.\n\n"));
        }
        Support::FailClosed(note) => {
            out.push_str(&format!(
                "- ⛔ `{to}` on `{platform}` is **fail-closed** (lab-assignable for evidence, not yet product-supported): {note}\n\n"
            ));
        }
        Support::Planned(note) => {
            out.push_str(&format!(
                "- 📋 `{to}` on `{platform}` is **planned**, not yet implemented: {note}\n\n"
            ));
        }
        Support::Blocked(note) => {
            out.push_str(&format!(
                "## Result: 🚫 Platform-Blocked\n\n- `{to}` is not available on `{platform}`: {note}\n"
            ));
            return Ok(out);
        }
    }

    // Transition mechanics (mirror of role_presets::transition_plan).
    let plan = plan_transition(from_p, to_p);
    out.push_str("## Transition\n");
    let banner = match plan.kind {
        TransitionKind::Identity => "✅ No-op (already in role)",
        TransitionKind::LocalOnly => "✅ Allowed — local-only (config write + daemon reload)",
        TransitionKind::SignedMembership => {
            "✅ Allowed — requires an owner-signed membership update"
        }
        TransitionKind::Irreversible => "⚠️ Allowed but IRREVERSIBLE (destructive, one-way)",
        TransitionKind::Blocked => "🚫 Blocked",
    };
    out.push_str(&format!(
        "- **Kind:** {banner}\n- **Why:** {}\n",
        plan.reason
    ));
    if plan.kind == TransitionKind::Blocked {
        return Ok(out);
    }
    if let Some((f, t)) = plan.primary_change {
        out.push_str(&format!("- **Primary role change:** {f} → {t}\n"));
    }
    if !plan.adds.is_empty() {
        out.push_str(&format!(
            "- **Capabilities added:** {}\n",
            plan.adds.join(", ")
        ));
    }
    if !plan.removes.is_empty() {
        out.push_str(&format!(
            "- **Capabilities removed:** {}\n",
            plan.removes.join(", ")
        ));
    }

    out.push_str("\n## Required side-effects (ordered)\n");
    if plan.kind == TransitionKind::Irreversible {
        out.push_str("- Requires typed factory-reset acknowledgement before proceeding.\n");
        out.push_str("- Wipes node identity and re-enrolls fresh.\n");
    }
    // Service deploy/undeploy, in the safe order.
    if plan.relay_deploy {
        out.push_str("- **Deploy** the `rustynet-relay` sibling service and verify it is Running BEFORE advertising the capability in the signed bundle (deploy-then-advertise).\n");
    }
    if plan.adds.contains(&"serves_exit") {
        out.push_str(
            "- **Deploy** exit forwarding + NAT BEFORE advertising the exit capability.\n",
        );
    }
    if plan.removes.contains(&"serves_exit") {
        out.push_str("- **Tear down** exit NAT/forwarding BEFORE revoking the capability (NAT residue after revocation is a release-blocking defect).\n");
    }
    if plan.relay_undeploy {
        out.push_str("- **Undeploy** the `rustynet-relay` service BEFORE the revocation bundle (fail-closed: keep previous state on undeploy failure).\n");
    }
    if to_p == Preset::Anchor {
        out.push_str("- Anchor brings up: bundle-pull listener, enrollment endpoint (loopback by default), gossip seed, and port-mapping authority (lex-min lease).\n");
    }
    out.push_str("- Emit an append-only audit log entry (timestamp, from, to, side-effects, outcome, operator).\n");

    if matches!(support, Support::FailClosed(_)) {
        out.push_str("\n_Note: this role is fail-closed on this platform — the transition validates, but the role will not be product-active until a green standard-orchestrator run is archived._\n");
    }
    Ok(out)
}

// ── Platform support (mirror of is_supported_for_platform) ────────────

enum Support {
    Supported,
    FailClosed(&'static str),
    Planned(&'static str),
    Blocked(&'static str),
}

/// Mirror of `vm_lab/orchestrator/role.rs::is_supported_for_platform` +
/// `rustynet-operator/src/role.rs::is_blind_exit_supported_host`.
fn role_support(role: Preset, platform: &str) -> Support {
    let p = platform.to_lowercase();
    match (role, p.as_str()) {
        // Mobile is consume-only by OS constraint.
        (Preset::Client, "ios" | "android") => {
            Support::Planned("mobile is client-only; adapter not yet shipped")
        }
        (_, "ios" | "android") => Support::Blocked("mobile is client-only by design"),

        // Linux: everything is live-evidenced.
        (_, "linux") => Support::Supported,

        // blind_exit host gate.
        (Preset::BlindExit, "macos") => Support::Supported,
        (Preset::BlindExit, "windows") => Support::Blocked("not a supported blind_exit host"),

        // exit: macOS maps to the blind_exit PF posture (supported);
        // Windows is fail-closed until W5.4 live evidence.
        (Preset::Exit, "macos") => Support::Supported,
        (Preset::Exit, "windows") => {
            Support::FailClosed("gated until W5.4 WinNAT/HNS live evidence")
        }

        // anchor/relay: Linux-only today; macOS+Windows lab-assignable but
        // fail-closed pending a Phase-8 green run.
        (Preset::Relay | Preset::Anchor, "macos" | "windows") => {
            Support::FailClosed("lab-assignable; pending Phase-8 cross-OS green run")
        }

        // client/admin on macOS + Windows.
        (Preset::Client | Preset::Admin, "macos" | "windows") => Support::Supported,

        // Unknown platform: fail closed (default-deny). All known
        // (role, platform) pairs are covered by the arms above.
        _ => Support::Blocked("unknown platform; use linux, macos, windows, ios, or android"),
    }
}

fn render_platform_support(feature: Option<&str>, platform: Option<&str>) -> String {
    let platforms = ["linux", "macos", "windows", "ios", "android"];
    let roles = [
        Preset::Client,
        Preset::Admin,
        Preset::Exit,
        Preset::BlindExit,
        Preset::Relay,
        Preset::Anchor,
    ];
    let feat = feature.map(|f| f.to_lowercase());
    let plat = platform.map(|p| p.to_lowercase());

    let mut out = String::from("# Platform Support Matrix\n\n");
    out.push_str("_Mirrored from the live code gate (is_supported_for_platform + is_blind_exit_supported_host)._\n\n## Roles\n");
    for role in roles {
        if let Some(f) = &feat
            && !role.as_str().contains(f.as_str())
        {
            continue;
        }
        for pf in platforms {
            if let Some(p) = &plat
                && pf != p
            {
                continue;
            }
            let (icon, label, note) = match role_support(role, pf) {
                Support::Supported => ("✅", "supported", ""),
                Support::FailClosed(n) => ("⛔", "fail-closed", n),
                Support::Planned(n) => ("📋", "planned", n),
                Support::Blocked(n) => ("🚫", "blocked", n),
            };
            if note.is_empty() {
                out.push_str(&format!(
                    "- {icon} **{}** on **{pf}**: {label}\n",
                    role.as_str()
                ));
            } else {
                out.push_str(&format!(
                    "- {icon} **{}** on **{pf}**: {label} ({note})\n",
                    role.as_str()
                ));
            }
        }
    }

    // Non-role platform features.
    out.push_str("\n## Features\n");
    for entry in PLATFORM_FEATURES {
        if let Some(f) = &feat
            && !entry.feature.to_lowercase().contains(f.as_str())
        {
            continue;
        }
        if let Some(p) = &plat
            && entry.platform != p.as_str()
        {
            continue;
        }
        out.push_str(&format!(
            "- **{}** on **{}**: {} — {}\n",
            entry.feature, entry.platform, entry.status, entry.note
        ));
    }

    out.push_str("\n## Legend\n- ✅ supported (live evidence) · ⛔ fail-closed (implemented, lab-assignable, pending live evidence) · 📋 planned · 🚫 blocked\n");
    out
}

struct FeatureSupport {
    feature: &'static str,
    platform: &'static str,
    status: &'static str,
    note: &'static str,
}

static PLATFORM_FEATURES: &[FeatureSupport] = &[
    FeatureSupport {
        feature: "killswitch",
        platform: "linux",
        status: "supported",
        note: "nftables pre-start and post-start",
    },
    FeatureSupport {
        feature: "killswitch",
        platform: "macos",
        status: "fail-closed",
        note: "pf anchor available; pre-killswitch not yet mandatory",
    },
    FeatureSupport {
        feature: "killswitch",
        platform: "windows",
        status: "fail-closed",
        note: "netsh-based; IPv4 LAN egress allow-all (RN-06); WFP migration planned",
    },
    FeatureSupport {
        feature: "wireguard-kernel",
        platform: "linux",
        status: "supported",
        note: "in-kernel wireguard.ko",
    },
    FeatureSupport {
        feature: "wireguard-userspace",
        platform: "macos",
        status: "supported",
        note: "boringtun userspace backend",
    },
    FeatureSupport {
        feature: "wireguard-nt",
        platform: "windows",
        status: "supported",
        note: "WireGuard-NT kernel driver",
    },
    FeatureSupport {
        feature: "dpapi-secrets",
        platform: "windows",
        status: "supported",
        note: "DPAPI-protected blobs under ProgramData\\RustyNet\\secrets",
    },
    FeatureSupport {
        feature: "keychain-secrets",
        platform: "macos",
        status: "supported",
        note: "macOS keychain key custody",
    },
    FeatureSupport {
        feature: "ipv6-dataplane",
        platform: "linux",
        status: "supported",
        note: "dual-stack with v6 candidate gathering",
    },
    FeatureSupport {
        feature: "upnp-natpmp-pcp",
        platform: "linux",
        status: "supported",
        note: "gateway detection via /proc/net/route",
    },
];

// ── Crate structure + which_crate ─────────────────────────────────────

struct CrateInfo {
    name: &'static str,
    layer: &'static str,
    summary: &'static str,
}

static CRATES: &[CrateInfo] = &[
    CrateInfo {
        name: "rustynet-control",
        layer: "domain",
        summary: "Signed membership, enrollment, gossip primitives, role presets (role_presets.rs). Transport-agnostic.",
    },
    CrateInfo {
        name: "rustynet-policy",
        layer: "domain",
        summary: "ACL and policy evaluation engine. Transport-agnostic.",
    },
    CrateInfo {
        name: "rustynet-crypto",
        layer: "domain",
        summary: "Cryptographic primitives (signing, verification, key types). No custom crypto.",
    },
    CrateInfo {
        name: "rustynet-dns-zone",
        layer: "domain",
        summary: "Magic DNS signed zone schema and validation.",
    },
    CrateInfo {
        name: "rustynet-local-security",
        layer: "domain",
        summary: "Local security verification (runtime ACLs, key custody, service hardening).",
    },
    CrateInfo {
        name: "rustynet-sysinfo",
        layer: "domain",
        summary: "Host OS detection, interface enumeration.",
    },
    CrateInfo {
        name: "rustynet-operator",
        layer: "domain",
        summary: "Operator UX, config, wizards, role host eligibility (role.rs).",
    },
    CrateInfo {
        name: "rustynet-backend-api",
        layer: "backend",
        summary: "Backend trait definitions — what every backend must implement.",
    },
    CrateInfo {
        name: "rustynet-backend-wireguard",
        layer: "backend",
        summary: "Production WireGuard backend (kernel + userspace).",
    },
    CrateInfo {
        name: "rustynet-backend-userspace",
        layer: "backend",
        summary: "Userspace WireGuard backend (boringtun).",
    },
    CrateInfo {
        name: "rustynet-backend-stub",
        layer: "backend",
        summary: "Stub backend for testing.",
    },
    CrateInfo {
        name: "rustynetd",
        layer: "daemon-cli",
        summary: "Main daemon: WG management, STUN, gossip, relay client, killswitch, phase10 dataplane.",
    },
    CrateInfo {
        name: "rustynet-cli",
        layer: "daemon-cli",
        summary: "CLI + VM-lab orchestrator + live-lab wrappers. Largest crate.",
    },
    CrateInfo {
        name: "rustynet-relay",
        layer: "daemon-cli",
        summary: "Production relay binary (frame forwarding between peers).",
    },
    CrateInfo {
        name: "rustynet-windows-native",
        layer: "platform",
        summary: "Windows-specific native code (WFP, named pipes, DPAPI).",
    },
    CrateInfo {
        name: "rustynet-mcp",
        layer: "tooling",
        summary: "MCP servers for AI agents (this crate).",
    },
    CrateInfo {
        name: "rustynet-xtask",
        layer: "tooling",
        summary: "Convenience gate runner (fmt → check → clippy → test).",
    },
];

fn layer_boundary(layer: &str) -> &'static str {
    match layer {
        "domain" => {
            "Transport-agnostic. MUST NOT import backend or WireGuard types — keep policy/domain logic backend-free. Enforced by scripts/ci/check_backend_boundary_leakage.sh."
        }
        "backend" => {
            "Backend adapter. WireGuard/transport-specific types live ONLY here, behind rustynet-backend-api traits. Do not leak these types into domain crates."
        }
        "daemon-cli" => {
            "Wires domain crates + backends together via backend interfaces. Do not leak backend types into domain logic; depend on traits, not concrete backends."
        }
        "platform" => {
            "OS-specific native integration boundary. Keep platform calls behind a stable interface; non-Rust only for unavoidable OS boundaries."
        }
        "tooling" => "Dev/CI tooling. Not in the production trust path.",
        _ => "Unknown layer.",
    }
}

fn render_crate_structure() -> String {
    let mut out = String::from("# Workspace Crate Structure\n\n");
    for layer in ["domain", "backend", "daemon-cli", "platform", "tooling"] {
        let title = match layer {
            "domain" => "Core / Domain (transport-agnostic)",
            "backend" => "Backend Adapters (transport-specific)",
            "daemon-cli" => "Daemon & CLI",
            "platform" => "Platform-Specific",
            "tooling" => "Tooling",
            _ => layer,
        };
        out.push_str(&format!("## {title}\n"));
        for c in CRATES.iter().filter(|c| c.layer == layer) {
            out.push_str(&format!("- **`{}`** — {}\n", c.name, c.summary));
        }
        out.push_str(&format!("  - _Boundary:_ {}\n", layer_boundary(layer)));
        out.push('\n');
    }
    out
}

fn which_crate(path: &str) -> String {
    if path.is_empty() {
        return "Missing required parameter: path".into();
    }
    // Find `crates/<name>/` in the path.
    let owning = path
        .split('/')
        .collect::<Vec<_>>()
        .windows(2)
        .find_map(|w| {
            if w[0] == "crates" {
                CRATES.iter().find(|c| c.name == w[1])
            } else {
                None
            }
        });

    match owning {
        Some(c) => format!(
            "# `{}`\n\n- **Path:** `{}`\n- **Layer:** {}\n- **What it does:** {}\n\n## Boundary rule\n{}\n",
            c.name,
            path,
            c.layer,
            c.summary,
            layer_boundary(c.layer)
        ),
        None => {
            let area = if path.starts_with("documents/") {
                "Documentation (not a crate). Use get_document / find_in_docs / get_active_ledger."
            } else if path.starts_with("scripts/") {
                "Scripts (CI gates, vm_lab helpers). Not a crate; run via the gate-runner / lab-state MCP servers."
            } else {
                "Not under crates/. No owning crate."
            };
            format!(
                "# No owning crate for `{path}`\n\n{area}\n\nKnown crates: {}",
                CRATES.iter().map(|c| c.name).collect::<Vec<_>>().join(", ")
            )
        }
    }
}

// ── Static reference data ─────────────────────────────────────────────

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

## VM Lab Entry Points (CLI / lab-state MCP)
- `ops vm-lab-discover-local-utm-summary` — discover VMs, quick summary
- `ops vm-lab-orchestrate-live-lab` — one-shot: discover → restart → setup → run → diagnose
- `ops vm-lab-run-live-lab` — run full suite against a profile
- `ops vm-lab-diagnose-live-lab-failure` — collect failure context
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transition_admin_client_is_local_only() {
        let p = plan_transition(Preset::Admin, Preset::Client);
        assert_eq!(p.kind, TransitionKind::LocalOnly);
    }

    #[test]
    fn transition_client_exit_is_signed_with_exit_cap() {
        let p = plan_transition(Preset::Client, Preset::Exit);
        assert_eq!(p.kind, TransitionKind::SignedMembership);
        assert!(p.adds.contains(&"serves_exit"));
    }

    #[test]
    fn transition_from_blind_exit_blocked() {
        let p = plan_transition(Preset::BlindExit, Preset::Client);
        assert_eq!(p.kind, TransitionKind::Blocked);
    }

    #[test]
    fn transition_to_blind_exit_irreversible() {
        let p = plan_transition(Preset::Client, Preset::BlindExit);
        assert_eq!(p.kind, TransitionKind::Irreversible);
    }

    #[test]
    fn transition_relay_to_client_undeploys_relay() {
        let p = plan_transition(Preset::Relay, Preset::Client);
        assert!(p.relay_undeploy);
        assert!(!p.relay_deploy);
    }

    #[test]
    fn transition_client_to_anchor_deploys_relay() {
        let p = plan_transition(Preset::Client, Preset::Anchor);
        assert!(p.relay_deploy);
        assert_eq!(p.kind, TransitionKind::SignedMembership);
    }

    #[test]
    fn platform_gate_matches_code() {
        // Windows blind_exit is a blocked host.
        assert!(matches!(
            role_support(Preset::BlindExit, "windows"),
            Support::Blocked(_)
        ));
        // macOS blind_exit + exit are supported.
        assert!(matches!(
            role_support(Preset::BlindExit, "macos"),
            Support::Supported
        ));
        assert!(matches!(
            role_support(Preset::Exit, "macos"),
            Support::Supported
        ));
        // Windows exit is fail-closed (NOT blocked) — the key bug we fixed.
        assert!(matches!(
            role_support(Preset::Exit, "windows"),
            Support::FailClosed(_)
        ));
        // Anchor/relay fail-closed off Linux.
        assert!(matches!(
            role_support(Preset::Anchor, "windows"),
            Support::FailClosed(_)
        ));
        assert!(matches!(
            role_support(Preset::Relay, "macos"),
            Support::FailClosed(_)
        ));
        // Linux supports everything.
        assert!(matches!(
            role_support(Preset::Anchor, "linux"),
            Support::Supported
        ));
        // Unknown platform fails closed (default-deny).
        assert!(matches!(
            role_support(Preset::Client, "freebsd"),
            Support::Blocked(_)
        ));
        assert!(matches!(
            role_support(Preset::Exit, "plan9"),
            Support::Blocked(_)
        ));
    }

    #[test]
    fn role_transition_and_platform_support_agree() {
        // The two tools must never contradict: a role blocked for transition
        // must show blocked in the matrix, and vice-versa.
        for role in [
            Preset::Exit,
            Preset::BlindExit,
            Preset::Relay,
            Preset::Anchor,
        ] {
            for platform in ["linux", "macos", "windows", "ios", "android"] {
                let transition =
                    describe_role_transition("client", role.as_str(), platform).unwrap_or_default();
                let blocked_in_transition = transition.contains("Platform-Blocked");
                let blocked_in_matrix = matches!(role_support(role, platform), Support::Blocked(_));
                assert_eq!(
                    blocked_in_transition,
                    blocked_in_matrix,
                    "disagreement for {} on {platform}",
                    role.as_str()
                );
            }
        }
    }

    #[test]
    fn which_crate_resolves_domain_crate() {
        let out = which_crate("crates/rustynet-policy/src/eval.rs");
        assert!(out.contains("rustynet-policy"));
        assert!(out.contains("domain"));
        assert!(out.contains("MUST NOT import backend"));
    }

    #[test]
    fn which_crate_handles_non_crate_path() {
        let out = which_crate("documents/Requirements.md");
        assert!(out.contains("Documentation"));
    }

    #[test]
    fn parse_findings_expands_range_and_counts() {
        let doc = "\
## 18. Master finding-status tracker

| ID | Sev | Domain | Status | Ref |
|---|---|---|---|---|
| RN-01 | High | Untrusted input | **Fixed** | RL-1 |
| RN-02 | High | Dataplane | Open | §11 |
| RN-21 | Low | Crypto | **Accepted** (fail-closed) | RL note |
| RN-34–38 | Info | various | Open | — |

## 19. Next
";
        let f = parse_findings_table(doc);
        // 3 explicit + 5 expanded = 8
        assert_eq!(f.len(), 8);
        assert!(f.iter().any(|x| x.id == "RN-34" && x.severity == "Info"));
        assert!(f.iter().any(|x| x.id == "RN-38"));
        let fixed = f.iter().filter(|x| x.status == "Fixed").count();
        assert_eq!(fixed, 1);
        let accepted = f.iter().filter(|x| x.status == "Accepted").count();
        assert_eq!(accepted, 1);
    }

    #[test]
    fn severity_filter_normalizes_med() {
        assert!(severity_matches("Med", "medium"));
        assert!(severity_matches("Medium", "Med"));
        assert!(!severity_matches("Low", "High"));
    }
}
