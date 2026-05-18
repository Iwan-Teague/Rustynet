#![allow(dead_code)]
use crate::vm_lab::orchestrator::role::NodeRole;

/// Translate the legacy per-role `--<role>-vm <alias>` CLI flags into the
/// `Vec<NodeRoleAssignment>` shape used by `--node <alias>:<role>`.
///
/// Mapping mirrors `scripts/e2e/live_linux_lab_orchestrator.sh`:
///   --exit-vm          → `<alias>:exit`
///   --client-vm        → `<alias>:client`
///   --entry-vm         → `<alias>:entry`
///   --aux-vm           → `<alias>:aux`
///   --extra-vm         → `<alias>:extra`
///   --fifth-client-vm  → `<alias>:client` (bash treats this as a 2nd client)
///   --windows-vm       → `<alias>:client` (bash post-validate treats it as a client peer)
///
/// Aliases that are `Some("")` after trimming are silently skipped, matching
/// the bash orchestrator's "missing flag = role not assigned" semantics.
pub fn translate_legacy_role_flags(
    exit_vm: Option<&str>,
    client_vm: Option<&str>,
    entry_vm: Option<&str>,
    aux_vm: Option<&str>,
    extra_vm: Option<&str>,
    fifth_client_vm: Option<&str>,
    windows_vm: Option<&str>,
) -> Vec<NodeRoleAssignment> {
    let mut out = Vec::new();
    let push_if_present =
        |out: &mut Vec<NodeRoleAssignment>, alias: Option<&str>, role: NodeRole| {
            if let Some(a) = alias {
                let trimmed = a.trim();
                if !trimmed.is_empty() {
                    out.push(NodeRoleAssignment {
                        alias: trimmed.to_owned(),
                        role,
                    });
                }
            }
        };
    push_if_present(&mut out, exit_vm, NodeRole::Exit);
    push_if_present(&mut out, client_vm, NodeRole::Client);
    push_if_present(&mut out, entry_vm, NodeRole::Entry);
    push_if_present(&mut out, aux_vm, NodeRole::Aux);
    push_if_present(&mut out, extra_vm, NodeRole::Extra);
    push_if_present(&mut out, fifth_client_vm, NodeRole::Client);
    push_if_present(&mut out, windows_vm, NodeRole::Client);
    out
}

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
        return Err("--node argument must not be empty".to_owned());
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
        alias: alias.to_owned(),
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
        assert_eq!(result.role, NodeRole::Custom("relay".to_owned()));
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

    #[test]
    fn translate_legacy_role_flags_full_five_node_matches_node_flag_equivalents() {
        // Legacy: --exit-vm A --client-vm B --entry-vm C --aux-vm D --extra-vm E
        let translated = translate_legacy_role_flags(
            Some("A"),
            Some("B"),
            Some("C"),
            Some("D"),
            Some("E"),
            None,
            None,
        );
        // Equivalent --node form
        let via_node: Vec<NodeRoleAssignment> =
            ["A:exit", "B:client", "C:entry", "D:aux", "E:extra"]
                .iter()
                .map(|s| parse_node_role_arg(s).unwrap())
                .collect();
        assert_eq!(translated, via_node);
    }

    #[test]
    fn translate_legacy_role_flags_fifth_client_maps_to_second_client() {
        let translated =
            translate_legacy_role_flags(Some("A"), Some("B"), None, None, None, Some("F"), None);
        let via_node: Vec<NodeRoleAssignment> = ["A:exit", "B:client", "F:client"]
            .iter()
            .map(|s| parse_node_role_arg(s).unwrap())
            .collect();
        assert_eq!(translated, via_node);
    }

    #[test]
    fn translate_legacy_role_flags_windows_vm_maps_to_client() {
        let translated = translate_legacy_role_flags(
            Some("L1"),
            Some("L2"),
            None,
            None,
            None,
            None,
            Some("WIN"),
        );
        let via_node: Vec<NodeRoleAssignment> = ["L1:exit", "L2:client", "WIN:client"]
            .iter()
            .map(|s| parse_node_role_arg(s).unwrap())
            .collect();
        assert_eq!(translated, via_node);
    }

    #[test]
    fn translate_legacy_role_flags_skips_none_and_blank_aliases() {
        let translated =
            translate_legacy_role_flags(Some("A"), None, Some("   "), None, Some(""), None, None);
        let via_node: Vec<NodeRoleAssignment> = ["A:exit"]
            .iter()
            .map(|s| parse_node_role_arg(s).unwrap())
            .collect();
        assert_eq!(translated, via_node);
    }

    #[test]
    fn translate_legacy_role_flags_trims_whitespace_in_alias() {
        let translated = translate_legacy_role_flags(
            Some("  spaced-exit  "),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(translated.len(), 1);
        assert_eq!(translated[0].alias, "spaced-exit");
        assert_eq!(translated[0].role, NodeRole::Exit);
    }

    #[test]
    fn translate_legacy_role_flags_empty_when_nothing_provided() {
        let translated = translate_legacy_role_flags(None, None, None, None, None, None, None);
        assert!(translated.is_empty());
    }
}
