#![allow(dead_code)]
use crate::vm_lab::orchestrator::role::NodeRole;

/// Binding of a node alias to a role for one lab run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRoleAssignment {
    pub alias: String,
    pub role: NodeRole,
}

/// Parse `"<alias>:<role>"` from a CLI `--node` argument.
/// Returns `Err` on empty input, missing colon, empty alias/role, or
/// unknown role name.
pub fn parse_node_role_arg(s: &str) -> Result<NodeRoleAssignment, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("--node argument must not be empty".to_string());
    }
    let (alias, role_str) = s
        .split_once(':')
        .ok_or_else(|| format!("--node argument '{s}' must be in the form '<alias>:<role>'"))?;
    let alias = alias.trim();
    let role_str = role_str.trim();
    if alias.is_empty() {
        return Err(format!("alias part of '--node {s}' must not be empty"));
    }
    if role_str.is_empty() {
        return Err(format!("role part of '--node {s}' must not be empty"));
    }
    let role = NodeRole::parse(role_str)?;
    Ok(NodeRoleAssignment {
        alias: alias.to_string(),
        role,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_all_named_roles() {
        let cases = [
            ("node-a:exit", NodeRole::Exit),
            ("node-b:client", NodeRole::Client),
            ("node-c:entry", NodeRole::Entry),
            ("node-d:aux", NodeRole::Aux),
            ("node-e:extra", NodeRole::Extra),
        ];
        for (input, expected_role) in cases {
            let result = parse_node_role_arg(input).unwrap();
            assert_eq!(result.role, expected_role, "input: {input}");
        }
    }

    #[test]
    fn parse_custom_role() {
        let result = parse_node_role_arg("my-device:custom-relay").unwrap();
        assert_eq!(result.alias, "my-device");
        assert_eq!(result.role, NodeRole::Custom("relay".to_string()));
    }

    #[test]
    fn parse_rejects_empty() {
        assert!(parse_node_role_arg("").is_err());
        assert!(parse_node_role_arg("   ").is_err());
    }

    #[test]
    fn parse_rejects_missing_colon() {
        assert!(parse_node_role_arg("nodeexit").is_err());
        assert!(parse_node_role_arg("node-exit").is_err());
    }

    #[test]
    fn parse_rejects_empty_alias() {
        assert!(parse_node_role_arg(":exit").is_err());
    }

    #[test]
    fn parse_rejects_empty_role() {
        assert!(parse_node_role_arg("node:").is_err());
    }

    #[test]
    fn parse_rejects_unknown_role() {
        assert!(parse_node_role_arg("node:exti").is_err());
        assert!(parse_node_role_arg("node:worker").is_err());
        assert!(parse_node_role_arg("node:EXIT").is_err());
    }

    #[test]
    fn parse_alias_preserved() {
        let result = parse_node_role_arg("debian-headless-1:exit").unwrap();
        assert_eq!(result.alias, "debian-headless-1");
        assert_eq!(result.role, NodeRole::Exit);
    }
}
