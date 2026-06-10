//! Per-work-unit agent invocation: the argv builder for the headless agent and
//! the cell-spec prompt renderer. Both are pure — this module never spawns a
//! process (that is the executor's job, and is intentionally not exercised in
//! tests). See proposal §8.

use crate::vm_lab::overnight::backlog::{Cell, FrontierBacklog};

/// Spec for spawning one headless agent against one cell. Pure data; turned
/// into argv by [`build_agent_argv`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentSpawnSpec {
    /// Agent CLI binary (default `claude`).
    pub agent_cmd: String,
    /// Path to the MCP server config the agent should load.
    pub mcp_config_path: String,
    /// Tool allowlist passed to the agent.
    pub allowed_tools: Vec<String>,
    /// The rendered unit prompt.
    pub prompt: String,
}

/// Build the argv for the headless agent. Argv-only (no shell) per the
/// security baseline — the prompt and config path are passed as discrete
/// arguments, never interpolated into a shell string.
pub fn build_agent_argv(spec: &AgentSpawnSpec) -> Vec<String> {
    let mut argv = vec![spec.agent_cmd.clone(), "-p".to_owned(), spec.prompt.clone()];
    if !spec.mcp_config_path.is_empty() {
        argv.push("--mcp-config".to_owned());
        argv.push(spec.mcp_config_path.clone());
    }
    if !spec.allowed_tools.is_empty() {
        argv.push("--allowedTools".to_owned());
        argv.push(spec.allowed_tools.join(","));
    }
    argv
}

/// Render the cell-spec prompt the agent receives. It tells the agent exactly
/// which cell to green, where the sibling implementation is, that the live lab
/// is the oracle, and that it must commit on the overnight branch and journal a
/// next-step. Deterministic given its inputs.
pub fn render_unit_prompt(
    cell: &Cell,
    backlog: &FrontierBacklog,
    branch: &str,
    journal_pointer: &str,
) -> String {
    let sibling = cell
        .sibling_reference
        .as_deref()
        .unwrap_or("(no direct sibling — read the orchestrator stage for this role)");
    let prior_progress = cell
        .progress
        .as_deref()
        .map(|p| format!("\nPrior progress on this cell: {p}"))
        .unwrap_or_default();

    format!(
        "You are one work-unit of the overnight verified-plane march. Your job is to make a \
SINGLE (platform, role) live-lab cell go green, then stop.

TARGET CELL: {cell_id}
  state:        {state}
  stage:        {stage}
  sibling impl: {sibling}{prior}

GROUND RULES (non-negotiable):
- You are on branch `{branch}`. NEVER commit to main; NEVER `git push`.
- The live lab is the oracle. A cell is green only when its orchestrator stage \
passes on the real VM — not when you think it should.
- Investigate before editing: call repo-context (`get_role_transition`, \
`get_orchestrator_stages`, `which_crate`, `get_architecture_constraints`) and read the \
sibling implementation to learn the pattern.
- Implement or fix the missing piece for THIS cell only.
- Run gates (fmt -> check -> clippy -D warnings -> test) via the gate-runner MCP before \
any live-verify.
- Live-verify this cell only (lab-state MCP: rebuild_nodes fast path where possible).
- If gates pass AND the oracle is green -> commit with message \
`overnight: {cell_id} -> {stage} green`. Otherwise leave NO commit.
- Whatever the outcome, write a journal note ({journal}) recording your hypothesis, what \
you changed, the result, and an EXPLICIT next step so the next session can continue a \
large cell from where you stopped.
- If the fix would touch a security-sensitive crate (policy / control / crypto / \
local-security / dns-zone), do not auto-commit — flag it for adversarial review in the \
journal note and stop.

Frontier context:\n{summary}",
        cell_id = cell.id(),
        state = cell.state.as_str(),
        stage = cell.stage_hint,
        sibling = sibling,
        prior = prior_progress,
        branch = branch,
        journal = journal_pointer,
        summary = backlog.summary(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::VmGuestPlatform;
    use crate::vm_lab::overnight::backlog::{FrontierBacklog, MarchRole, PriorVerdicts};

    fn sample_backlog() -> FrontierBacklog {
        FrontierBacklog::build(
            &[VmGuestPlatform::Linux, VmGuestPlatform::Windows],
            &PriorVerdicts::new(),
        )
    }

    fn windows_relay_cell(b: &FrontierBacklog) -> Cell {
        b.cells
            .iter()
            .find(|c| c.platform == VmGuestPlatform::Windows && c.role == MarchRole::Relay)
            .cloned()
            .expect("windows relay")
    }

    #[test]
    fn argv_is_argv_only_with_discrete_arguments() {
        let spec = AgentSpawnSpec {
            agent_cmd: "claude".to_owned(),
            mcp_config_path: "/tmp/mcp.json".to_owned(),
            allowed_tools: vec!["Read".to_owned(), "Edit".to_owned()],
            prompt: "do the thing; rm -rf /".to_owned(), // metachars stay inert as one arg
        };
        let argv = build_agent_argv(&spec);
        assert_eq!(argv[0], "claude");
        assert_eq!(argv[1], "-p");
        // The whole prompt — including shell metacharacters — is a single argv
        // element, never split or interpreted.
        assert_eq!(argv[2], "do the thing; rm -rf /");
        assert!(argv.contains(&"--mcp-config".to_owned()));
        assert!(argv.contains(&"/tmp/mcp.json".to_owned()));
        assert!(argv.contains(&"--allowedTools".to_owned()));
        assert!(argv.contains(&"Read,Edit".to_owned()));
    }

    #[test]
    fn argv_omits_empty_optional_args() {
        let spec = AgentSpawnSpec {
            agent_cmd: "claude".to_owned(),
            mcp_config_path: String::new(),
            allowed_tools: vec![],
            prompt: "p".to_owned(),
        };
        let argv = build_agent_argv(&spec);
        assert_eq!(argv, vec!["claude", "-p", "p"]);
    }

    #[test]
    fn prompt_names_the_cell_and_forbids_main_and_push() {
        let b = sample_backlog();
        let cell = windows_relay_cell(&b);
        let prompt = render_unit_prompt(&cell, &b, "overnight/2026-06-09_x", "write_loop_note");
        assert!(prompt.contains("windows/relay"));
        assert!(prompt.contains("NEVER commit to main"));
        assert!(prompt.contains("NEVER `git push`"));
        assert!(prompt.contains("oracle"));
        assert!(prompt.contains("overnight/2026-06-09_x"));
    }

    #[test]
    fn prompt_includes_sibling_reference_for_unbuilt_cell() {
        let b = sample_backlog();
        let cell = windows_relay_cell(&b);
        let prompt = render_unit_prompt(&cell, &b, "br", "j");
        assert!(prompt.contains("deploy_relay.rs"));
    }

    #[test]
    fn prompt_warns_about_security_crates() {
        let b = sample_backlog();
        let cell = windows_relay_cell(&b);
        let prompt = render_unit_prompt(&cell, &b, "br", "j");
        assert!(prompt.contains("security-sensitive"));
    }

    #[test]
    fn prompt_is_deterministic() {
        let b = sample_backlog();
        let cell = windows_relay_cell(&b);
        let a = render_unit_prompt(&cell, &b, "br", "j");
        let c = render_unit_prompt(&cell, &b, "br", "j");
        assert_eq!(a, c);
    }
}
