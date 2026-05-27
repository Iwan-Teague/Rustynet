use crate::role::NodeRole;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuAction {
    ToggleConnection,
    SelectExitNode,
    DisableExit,
    AdvertiseDefaultRoute,
    LanAccessOn,
    LanAccessOff,
    Status,
    Netcheck,
    ShowPeers,
    ShowExitNodes,
    ShowConfig,
    SaveConfig,
    Doctor,
    ServiceStatus,
    RestartRuntime,
    RefreshTrust,
    RotateKey,
    RevokeKey,
    DisconnectCleanup,
    ShowRoleStatus,
    ListRoles,
    Quit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuItem {
    pub key: &'static str,
    pub label: &'static str,
    pub action: MenuAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuTree {
    pub title: &'static str,
    pub items: Vec<MenuItem>,
}

impl MenuTree {
    pub fn action_for_key(&self, key: &str) -> Option<MenuAction> {
        self.items
            .iter()
            .find(|item| item.key == key)
            .map(|item| item.action)
    }
}

pub fn menu_tree(role: NodeRole) -> MenuTree {
    match role {
        NodeRole::Admin => MenuTree {
            title: "Rustynet Admin Console",
            items: vec![
                item("1", "Toggle VPN connection", MenuAction::ToggleConnection),
                item("2", "Select exit node", MenuAction::SelectExitNode),
                item("3", "Disable exit node", MenuAction::DisableExit),
                item(
                    "4",
                    "Advertise default exit route",
                    MenuAction::AdvertiseDefaultRoute,
                ),
                item("5", "LAN access on", MenuAction::LanAccessOn),
                item("6", "LAN access off", MenuAction::LanAccessOff),
                item("7", "Status", MenuAction::Status),
                item("8", "Netcheck", MenuAction::Netcheck),
                item("9", "Peer list", MenuAction::ShowPeers),
                item("10", "Exit node list", MenuAction::ShowExitNodes),
                item("11", "Service status", MenuAction::ServiceStatus),
                item("12", "Restart runtime service", MenuAction::RestartRuntime),
                item("13", "Refresh signed trust", MenuAction::RefreshTrust),
                item("14", "Rotate key", MenuAction::RotateKey),
                item("15", "Revoke key", MenuAction::RevokeKey),
                item("16", "Doctor", MenuAction::Doctor),
                item("17", "Show config", MenuAction::ShowConfig),
                item("18", "Save config", MenuAction::SaveConfig),
                item("19", "Role status", MenuAction::ShowRoleStatus),
                item("20", "List roles", MenuAction::ListRoles),
                item("0", "Exit", MenuAction::Quit),
            ],
        },
        NodeRole::Client => MenuTree {
            title: "Rustynet Client Console",
            items: vec![
                item("1", "Toggle VPN connection", MenuAction::ToggleConnection),
                item("2", "Select exit node", MenuAction::SelectExitNode),
                item("3", "Disable exit node", MenuAction::DisableExit),
                item("4", "LAN access on", MenuAction::LanAccessOn),
                item("5", "LAN access off", MenuAction::LanAccessOff),
                item("6", "Status", MenuAction::Status),
                item("7", "Netcheck", MenuAction::Netcheck),
                item("8", "Peer list", MenuAction::ShowPeers),
                item("9", "Exit node list", MenuAction::ShowExitNodes),
                item("10", "Service status", MenuAction::ServiceStatus),
                item("11", "Restart runtime service", MenuAction::RestartRuntime),
                item("12", "Doctor", MenuAction::Doctor),
                item("13", "Show config", MenuAction::ShowConfig),
                item("14", "Save config", MenuAction::SaveConfig),
                item("15", "Role status", MenuAction::ShowRoleStatus),
                item("16", "List roles", MenuAction::ListRoles),
                item("0", "Exit", MenuAction::Quit),
            ],
        },
        NodeRole::BlindExit => MenuTree {
            title: "Rustynet Blind Exit Console",
            items: vec![
                item("1", "Toggle VPN connection", MenuAction::ToggleConnection),
                item("2", "Status", MenuAction::Status),
                item("3", "Netcheck", MenuAction::Netcheck),
                item("4", "Service status", MenuAction::ServiceStatus),
                item("5", "Restart runtime service", MenuAction::RestartRuntime),
                item("6", "Refresh signed trust", MenuAction::RefreshTrust),
                item("7", "Disconnect cleanup", MenuAction::DisconnectCleanup),
                item("8", "Doctor", MenuAction::Doctor),
                item("9", "Show config", MenuAction::ShowConfig),
                item("10", "Save config", MenuAction::SaveConfig),
                item("11", "Role status", MenuAction::ShowRoleStatus),
                item("0", "Exit", MenuAction::Quit),
            ],
        },
    }
}

fn item(key: &'static str, label: &'static str, action: MenuAction) -> MenuItem {
    MenuItem { key, label, action }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_menu_contains_privileged_actions() {
        let tree = menu_tree(NodeRole::Admin);
        assert_eq!(
            tree.action_for_key("4"),
            Some(MenuAction::AdvertiseDefaultRoute)
        );
        assert_eq!(tree.action_for_key("13"), Some(MenuAction::RefreshTrust));
    }

    #[test]
    fn client_menu_hides_admin_only_trust_refresh() {
        let tree = menu_tree(NodeRole::Client);
        assert!(
            !tree
                .items
                .iter()
                .any(|item| item.action == MenuAction::RefreshTrust)
        );
    }

    #[test]
    fn blind_exit_menu_is_restricted() {
        let tree = menu_tree(NodeRole::BlindExit);
        assert_eq!(
            tree.action_for_key("7"),
            Some(MenuAction::DisconnectCleanup)
        );
        assert!(
            !tree
                .items
                .iter()
                .any(|item| item.action == MenuAction::SelectExitNode)
        );
    }
}
