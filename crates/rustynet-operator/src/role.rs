use crate::host::HostProfile;
use crate::launch::{ExitChain, ExitChainHops, LanMode, LaunchProfile};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeRole {
    Admin,
    Client,
    BlindExit,
}

impl NodeRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Client => "client",
            Self::BlindExit => "blind_exit",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "admin" => Some(Self::Admin),
            "client" => Some(Self::Client),
            "blind_exit" => Some(Self::BlindExit),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RolePreset {
    Anchor,
    Admin,
    Exit,
    Relay,
    Nas,
    Llm,
    Client,
    BlindExit,
}

impl RolePreset {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Anchor => "anchor",
            Self::Admin => "admin",
            Self::Exit => "exit",
            Self::Relay => "relay",
            Self::Nas => "nas",
            Self::Llm => "llm",
            Self::Client => "client",
            Self::BlindExit => "blind_exit",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "anchor" => Some(Self::Anchor),
            "admin" => Some(Self::Admin),
            "exit" => Some(Self::Exit),
            "relay" => Some(Self::Relay),
            "nas" => Some(Self::Nas),
            "llm" => Some(Self::Llm),
            "client" => Some(Self::Client),
            "blind_exit" => Some(Self::BlindExit),
            _ => None,
        }
    }

    pub fn primary_role(self) -> NodeRole {
        match self {
            Self::Client => NodeRole::Client,
            Self::BlindExit => NodeRole::BlindExit,
            Self::Admin | Self::Exit | Self::Relay | Self::Anchor | Self::Nas | Self::Llm => {
                NodeRole::Admin
            }
        }
    }
}

pub fn is_blind_exit_supported_host(host: HostProfile) -> bool {
    matches!(host, HostProfile::Linux | HostProfile::Macos)
}

pub fn normalize_role(
    raw_role: Option<&str>,
    raw_preset: Option<&str>,
    setup_complete: bool,
    host: HostProfile,
) -> (NodeRole, Option<RolePreset>, Vec<String>) {
    let mut warnings = Vec::new();

    let mut role = match raw_role.map(str::trim).filter(|value| !value.is_empty()) {
        None => {
            if setup_complete {
                NodeRole::Admin
            } else {
                NodeRole::Client
            }
        }
        Some(value) => match NodeRole::parse(value) {
            Some(role) => role,
            None => {
                warnings.push(format!(
                    "Invalid NODE_ROLE='{value}', defaulting to 'client'."
                ));
                NodeRole::Client
            }
        },
    };
    if role == NodeRole::BlindExit && !is_blind_exit_supported_host(host) {
        warnings.push(
            "blind_exit role is supported only on Linux/macOS hosts. Reverting to client role."
                .to_owned(),
        );
        role = NodeRole::Client;
    }

    let preset = match raw_preset.map(str::trim).filter(|value| !value.is_empty()) {
        None => None,
        Some(value) => match RolePreset::parse(value) {
            Some(preset) => Some(preset),
            None => {
                warnings.push(format!("Invalid SETUP_ROLE_PRESET='{value}', clearing."));
                None
            }
        },
    };
    if let Some(preset) = preset {
        let expected_primary = preset.primary_role();
        if role != expected_primary {
            warnings.push(format!(
                "NODE_ROLE='{}' does not match SETUP_ROLE_PRESET='{}'; coercing to '{}'.",
                role.as_str(),
                preset.as_str(),
                expected_primary.as_str()
            ));
            role = expected_primary;
        }
    }

    (role, preset, warnings)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RolePolicyState {
    pub node_role: NodeRole,
    pub manual_peer_override: bool,
    pub auto_refresh_trust: bool,
    pub default_launch_profile: LaunchProfile,
    pub auto_port_forward_exit: bool,
    pub exit_chain: ExitChain,
    pub auto_launch_on_start: bool,
    pub auto_launch_exit_node_id: Option<String>,
    pub auto_launch_lan_mode: LanMode,
    pub fail_closed_ssh_allow: bool,
    pub fail_closed_ssh_cidrs: Vec<String>,
}

pub fn enforce_role_policy_defaults(
    state: &mut RolePolicyState,
    trust_signer_key_present: bool,
    trust_signer_key_path: &str,
) -> Vec<String> {
    let mut warnings = Vec::new();

    if state.node_role == NodeRole::Admin {
        return warnings;
    }

    state.manual_peer_override = false;

    if state.auto_refresh_trust && !trust_signer_key_present {
        warnings.push(format!(
            "Trust signer key {trust_signer_key_path} is unavailable; disabling AUTO_REFRESH_TRUST for role '{}'.",
            state.node_role.as_str()
        ));
        state.auto_refresh_trust = false;
    }

    match state.node_role {
        NodeRole::Client => {
            if matches!(
                state.default_launch_profile,
                LaunchProfile::QuickExitNode | LaunchProfile::QuickHybrid
            ) {
                warnings.push(format!(
                    "Launch profile '{}' is admin-only; forcing 'quick-connect' for client role.",
                    state.default_launch_profile.as_str()
                ));
                state.default_launch_profile = LaunchProfile::QuickConnect;
            }
            state.auto_port_forward_exit = false;
        }
        NodeRole::BlindExit => {
            if state.default_launch_profile != LaunchProfile::QuickExitNode {
                warnings.push(
                    "blind_exit role enforces default launch profile 'quick-exit-node'.".to_owned(),
                );
                state.default_launch_profile = LaunchProfile::QuickExitNode;
            }
            state.exit_chain = ExitChain {
                hops: ExitChainHops::One,
                entry: None,
                final_node: None,
            };
            state.auto_launch_on_start = true;
            state.auto_launch_exit_node_id = None;
            state.auto_launch_lan_mode = LanMode::Off;
            state.fail_closed_ssh_allow = false;
            state.fail_closed_ssh_cidrs.clear();
        }
        NodeRole::Admin => {}
    }

    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_policy_state() -> RolePolicyState {
        RolePolicyState {
            node_role: NodeRole::Client,
            manual_peer_override: false,
            auto_refresh_trust: false,
            default_launch_profile: LaunchProfile::QuickConnect,
            auto_port_forward_exit: false,
            exit_chain: ExitChain {
                hops: ExitChainHops::One,
                entry: None,
                final_node: None,
            },
            auto_launch_on_start: false,
            auto_launch_exit_node_id: None,
            auto_launch_lan_mode: LanMode::Skip,
            fail_closed_ssh_allow: false,
            fail_closed_ssh_cidrs: Vec::new(),
        }
    }

    #[test]
    fn empty_role_defaults_by_setup_state() {
        let (role, _, _) = normalize_role(None, None, true, HostProfile::Linux);
        assert_eq!(role, NodeRole::Admin);
        let (role, _, _) = normalize_role(None, None, false, HostProfile::Linux);
        assert_eq!(role, NodeRole::Client);
    }

    #[test]
    fn invalid_role_falls_back_to_client_with_warning() {
        let (role, _, warnings) = normalize_role(Some("wizard"), None, true, HostProfile::Linux);
        assert_eq!(role, NodeRole::Client);
        assert!(warnings.iter().any(|msg| msg.contains("Invalid NODE_ROLE")));
    }

    #[test]
    fn blind_exit_reverts_on_unsupported_host() {
        let (role, _, warnings) =
            normalize_role(Some("blind_exit"), None, true, HostProfile::Windows);
        assert_eq!(role, NodeRole::Client);
        assert!(
            warnings
                .iter()
                .any(|msg| msg.contains("Reverting to client"))
        );
    }

    #[test]
    fn preset_coerces_node_role() {
        let (role, preset, warnings) =
            normalize_role(Some("client"), Some("exit"), true, HostProfile::Linux);
        assert_eq!(role, NodeRole::Admin);
        assert_eq!(preset, Some(RolePreset::Exit));
        assert!(warnings.iter().any(|msg| msg.contains("coercing")));
    }

    #[test]
    fn service_hosting_presets_parse_and_map_to_admin_primary() {
        for (raw, expected) in [("nas", RolePreset::Nas), ("llm", RolePreset::Llm)] {
            let preset = RolePreset::parse(raw).expect("preset should parse");
            assert_eq!(preset, expected);
            assert_eq!(preset.as_str(), raw);
            assert_eq!(preset.primary_role(), NodeRole::Admin);
        }
    }

    #[test]
    fn service_hosting_preset_coerces_node_role_to_admin() {
        for raw in ["nas", "llm"] {
            let (role, preset, _) =
                normalize_role(Some("client"), Some(raw), true, HostProfile::Linux);
            assert_eq!(role, NodeRole::Admin);
            assert_eq!(preset, RolePreset::parse(raw));
        }
    }

    #[test]
    fn blind_exit_enforces_locked_posture() {
        let mut state = RolePolicyState {
            node_role: NodeRole::BlindExit,
            manual_peer_override: true,
            auto_refresh_trust: true,
            default_launch_profile: LaunchProfile::Menu,
            auto_port_forward_exit: true,
            exit_chain: ExitChain {
                hops: ExitChainHops::Two,
                entry: Some("a".to_owned()),
                final_node: Some("b".to_owned()),
            },
            auto_launch_on_start: false,
            auto_launch_exit_node_id: Some("x".to_owned()),
            auto_launch_lan_mode: LanMode::On,
            fail_closed_ssh_allow: true,
            fail_closed_ssh_cidrs: vec!["10.0.0.0/8".to_owned()],
        };
        let _ = enforce_role_policy_defaults(&mut state, true, "/etc/rustynet/trust.key");
        assert_eq!(state.default_launch_profile, LaunchProfile::QuickExitNode);
        assert_eq!(state.exit_chain.hops, ExitChainHops::One);
        assert!(state.exit_chain.entry.is_none());
        assert!(state.auto_launch_on_start);
        assert_eq!(state.auto_launch_lan_mode, LanMode::Off);
        assert!(!state.fail_closed_ssh_allow);
        assert!(state.fail_closed_ssh_cidrs.is_empty());
        assert!(!state.manual_peer_override);
    }

    #[test]
    fn client_downgrades_admin_only_profile_and_disables_port_forward() {
        let mut state = client_policy_state();
        state.default_launch_profile = LaunchProfile::QuickHybrid;
        state.auto_port_forward_exit = true;
        let warnings = enforce_role_policy_defaults(&mut state, true, "/etc/rustynet/trust.key");
        assert_eq!(state.default_launch_profile, LaunchProfile::QuickConnect);
        assert!(!state.auto_port_forward_exit);
        assert!(warnings.iter().any(|msg| msg.contains("admin-only")));
    }

    #[test]
    fn missing_trust_signer_disables_auto_refresh_for_non_admin() {
        let mut state = client_policy_state();
        state.auto_refresh_trust = true;
        let _ = enforce_role_policy_defaults(&mut state, false, "/etc/rustynet/trust.key");
        assert!(!state.auto_refresh_trust);
    }
}
