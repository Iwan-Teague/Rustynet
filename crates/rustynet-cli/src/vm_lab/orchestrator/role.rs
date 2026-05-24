#![allow(dead_code)]
use std::fmt;

use crate::vm_lab::VmGuestPlatform;
use rustynet_control::roles::RoleCapability;

/// OS-agnostic role definition. The 5 named roles match the bash
/// orchestrator's existing names so membership / traffic-test / role-switch
/// logic stays semantically identical.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NodeRole {
    Exit,
    Client,
    Entry,
    Aux,
    Extra,
    Custom(String),
}

impl NodeRole {
    /// Exactly one node per lab may hold an Exit role.
    pub fn is_unique_per_lab(&self) -> bool {
        matches!(self, NodeRole::Exit)
    }

    /// Returns true for roles that act as the membership-owner (signs bundles).
    pub fn is_membership_owner(&self) -> bool {
        matches!(self, NodeRole::Exit)
    }

    /// Role-platform matrix currently enforced by the Rust-native path.
    /// Windows Exit remains fail-closed until W5.4 live evidence is recorded.
    /// macOS Exit maps to the reviewed `blind_exit` PF posture.
    ///
    /// | Role   | Linux | Windows | macOS | iOS | Android |
    /// |--------|-------|---------|-------|-----|---------|
    /// | Exit   | ✓     | ✗       | ✓     | ✗   | ✗       |
    /// | Client | ✓     | ✓       | ✓     | ✗   | ✗       |
    /// | Entry  | ✓     | ✓       | ✓     | ✗   | ✗       |
    /// | Aux    | ✓     | ✓       | ✓     | ✗   | ✗       |
    /// | Extra  | ✓     | ✓       | ✓     | ✗   | ✗       |
    ///
    /// iOS and Android adapters fail closed with security-specific rejection
    /// messages (unreviewed key custody + connection model + daemon coverage).
    pub fn is_supported_for_platform(&self, platform: &VmGuestPlatform) -> bool {
        match platform {
            VmGuestPlatform::Ios | VmGuestPlatform::Android => false,
            VmGuestPlatform::Linux | VmGuestPlatform::Macos => true,
            VmGuestPlatform::Windows => !self.is_membership_owner(),
        }
    }

    /// Role-platform matrix for lab evidence generation. This is intentionally
    /// wider than `is_supported_for_platform`: Windows Exit must be assignable
    /// so the lab can produce the evidence required before posture promotion.
    /// Product support remains conservative until those artifacts pass.
    pub fn is_lab_assignable_for_platform(&self, platform: &VmGuestPlatform) -> bool {
        match platform {
            VmGuestPlatform::Ios | VmGuestPlatform::Android => false,
            VmGuestPlatform::Linux | VmGuestPlatform::Windows | VmGuestPlatform::Macos => true,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            NodeRole::Exit => "exit",
            NodeRole::Client => "client",
            NodeRole::Entry => "entry",
            NodeRole::Aux => "aux",
            NodeRole::Extra => "extra",
            NodeRole::Custom(s) => s.as_str(),
        }
    }

    pub fn daemon_node_role_for_platform(
        &self,
        platform: &VmGuestPlatform,
    ) -> Result<&'static str, String> {
        match platform {
            VmGuestPlatform::Linux | VmGuestPlatform::Windows => match self {
                NodeRole::Exit => Ok("admin"),
                NodeRole::Client | NodeRole::Entry | NodeRole::Aux | NodeRole::Extra => {
                    Ok("client")
                }
                NodeRole::Custom(label) => Err(format!(
                    "custom lab role '{label}' has no explicit daemon role mapping"
                )),
            },
            VmGuestPlatform::Macos => match self {
                NodeRole::Exit => Ok("blind_exit"),
                NodeRole::Client | NodeRole::Entry | NodeRole::Aux | NodeRole::Extra => {
                    Ok("client")
                }
                NodeRole::Custom(label) => Err(format!(
                    "custom lab role '{label}' has no explicit daemon role mapping"
                )),
            },
            VmGuestPlatform::Ios | VmGuestPlatform::Android => {
                Err(format!("{platform:?} has no supported daemon role mapping"))
            }
        }
    }

    pub fn product_capabilities_for_platform(
        &self,
        platform: &VmGuestPlatform,
    ) -> Result<Vec<RoleCapability>, String> {
        match platform {
            VmGuestPlatform::Ios | VmGuestPlatform::Android => Err(format!(
                "{platform:?} has no supported product capability mapping"
            )),
            VmGuestPlatform::Macos if matches!(self, NodeRole::Exit) => {
                Ok(vec![RoleCapability::BlindExit, RoleCapability::ExitServer])
            }
            VmGuestPlatform::Linux | VmGuestPlatform::Windows if matches!(self, NodeRole::Exit) => {
                Ok(vec![
                    RoleCapability::Anchor,
                    RoleCapability::ExitServer,
                    RoleCapability::RelayHost,
                ])
            }
            _ => match self {
                NodeRole::Client | NodeRole::Aux | NodeRole::Extra => {
                    Ok(vec![RoleCapability::Client])
                }
                NodeRole::Entry => Ok(vec![RoleCapability::Client, RoleCapability::EntryRelay]),
                NodeRole::Custom(label) => Err(format!(
                    "custom lab role '{label}' has no explicit product capability mapping"
                )),
                NodeRole::Exit => unreachable!("exit role handled above"),
            },
        }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim() {
            "exit" => Ok(NodeRole::Exit),
            "client" => Ok(NodeRole::Client),
            "entry" => Ok(NodeRole::Entry),
            "aux" => Ok(NodeRole::Aux),
            "extra" => Ok(NodeRole::Extra),
            other => {
                if let Some(label) = other.strip_prefix("custom-") {
                    if label.is_empty() {
                        return Err("custom role label must not be empty".to_owned());
                    }
                    Ok(NodeRole::Custom(label.to_owned()))
                } else {
                    Err(format!(
                        "unknown role '{other}'; expected one of: exit, client, entry, aux, extra, custom-<label>"
                    ))
                }
            }
        }
    }
}

impl fmt::Display for NodeRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_unique_per_lab_only_exit() {
        assert!(NodeRole::Exit.is_unique_per_lab());
        assert!(!NodeRole::Client.is_unique_per_lab());
        assert!(!NodeRole::Entry.is_unique_per_lab());
        assert!(!NodeRole::Aux.is_unique_per_lab());
        assert!(!NodeRole::Extra.is_unique_per_lab());
        assert!(!NodeRole::Custom("foo".to_owned()).is_unique_per_lab());
    }

    #[test]
    fn parse_named_roles() {
        assert_eq!(NodeRole::parse("exit").unwrap(), NodeRole::Exit);
        assert_eq!(NodeRole::parse("client").unwrap(), NodeRole::Client);
        assert_eq!(NodeRole::parse("entry").unwrap(), NodeRole::Entry);
        assert_eq!(NodeRole::parse("aux").unwrap(), NodeRole::Aux);
        assert_eq!(NodeRole::parse("extra").unwrap(), NodeRole::Extra);
    }

    #[test]
    fn parse_custom_role() {
        assert_eq!(
            NodeRole::parse("custom-foo").unwrap(),
            NodeRole::Custom("foo".to_owned())
        );
        assert_eq!(
            NodeRole::parse("custom-relay-test").unwrap(),
            NodeRole::Custom("relay-test".to_owned())
        );
    }

    #[test]
    fn parse_rejects_invalid() {
        assert!(NodeRole::parse("exti").is_err());
        assert!(NodeRole::parse("").is_err());
        assert!(NodeRole::parse("custom-").is_err());
        assert!(NodeRole::parse("EXIT").is_err());
        assert!(NodeRole::parse("worker").is_err());
    }

    #[test]
    fn is_supported_for_platform_linux_all_roles() {
        let roles = [
            NodeRole::Exit,
            NodeRole::Client,
            NodeRole::Entry,
            NodeRole::Aux,
            NodeRole::Extra,
        ];
        for role in &roles {
            assert!(
                role.is_supported_for_platform(&VmGuestPlatform::Linux),
                "{role:?} must be supported on Linux"
            );
        }
    }

    #[test]
    fn is_supported_for_platform_windows_fail_closed_for_exit_only() {
        assert!(
            !NodeRole::Exit.is_supported_for_platform(&VmGuestPlatform::Windows),
            "Windows Exit must remain fail-closed until W5.4 live evidence exists"
        );
        for role in &[
            NodeRole::Client,
            NodeRole::Entry,
            NodeRole::Aux,
            NodeRole::Extra,
        ] {
            assert!(
                role.is_supported_for_platform(&VmGuestPlatform::Windows),
                "{role:?} must be supported on Windows"
            );
        }
    }

    #[test]
    fn is_supported_for_platform_macos_exit_maps_to_blind_exit_pf_posture() {
        assert!(
            NodeRole::Exit.is_supported_for_platform(&VmGuestPlatform::Macos),
            "macOS Exit is supported through the reviewed blind_exit PF posture"
        );
        assert!(
            NodeRole::Exit.is_lab_assignable_for_platform(&VmGuestPlatform::Macos),
            "macOS Exit must be lab-assignable now that blind_exit PF parity exists"
        );
        assert_eq!(
            NodeRole::Exit
                .daemon_node_role_for_platform(&VmGuestPlatform::Macos)
                .unwrap(),
            "blind_exit"
        );
        assert_eq!(
            NodeRole::Exit
                .product_capabilities_for_platform(&VmGuestPlatform::Macos)
                .unwrap(),
            vec![RoleCapability::BlindExit, RoleCapability::ExitServer]
        );
    }

    #[test]
    fn is_supported_for_platform_ios_android_all_roles_blocked() {
        let roles = [
            NodeRole::Exit,
            NodeRole::Client,
            NodeRole::Entry,
            NodeRole::Aux,
            NodeRole::Extra,
        ];
        let unsupported = [VmGuestPlatform::Ios, VmGuestPlatform::Android];
        for role in &roles {
            for platform in &unsupported {
                assert!(
                    !role.is_supported_for_platform(platform),
                    "{role:?} must not be supported on {platform:?}"
                );
            }
        }
    }

    #[test]
    fn is_lab_assignable_for_platform_allows_windows_exit_evidence_without_support_promotion() {
        assert!(
            !NodeRole::Exit.is_supported_for_platform(&VmGuestPlatform::Windows),
            "Windows Exit must remain unsupported until live evidence promotes posture"
        );
        assert!(
            NodeRole::Exit.is_lab_assignable_for_platform(&VmGuestPlatform::Windows),
            "Windows Exit must be lab-assignable so live evidence can be generated"
        );
        assert!(
            NodeRole::Exit.is_lab_assignable_for_platform(&VmGuestPlatform::Macos),
            "macOS Exit is assignable through blind_exit PF parity"
        );
    }

    #[test]
    fn daemon_role_mapping_is_explicit_per_platform() {
        assert_eq!(
            NodeRole::Exit
                .daemon_node_role_for_platform(&VmGuestPlatform::Linux)
                .unwrap(),
            "admin"
        );
        assert_eq!(
            NodeRole::Exit
                .daemon_node_role_for_platform(&VmGuestPlatform::Macos)
                .unwrap(),
            "blind_exit"
        );
        assert_eq!(
            NodeRole::Entry
                .daemon_node_role_for_platform(&VmGuestPlatform::Windows)
                .unwrap(),
            "client"
        );
        assert!(
            NodeRole::Custom("relay-test".to_owned())
                .daemon_node_role_for_platform(&VmGuestPlatform::Linux)
                .is_err()
        );
    }

    #[test]
    fn product_capability_mapping_is_explicit_per_platform() {
        assert_eq!(
            NodeRole::Exit
                .product_capabilities_for_platform(&VmGuestPlatform::Linux)
                .unwrap(),
            vec![
                RoleCapability::Anchor,
                RoleCapability::ExitServer,
                RoleCapability::RelayHost,
            ]
        );
        assert_eq!(
            NodeRole::Exit
                .product_capabilities_for_platform(&VmGuestPlatform::Macos)
                .unwrap(),
            vec![RoleCapability::BlindExit, RoleCapability::ExitServer]
        );
        assert_eq!(
            NodeRole::Entry
                .product_capabilities_for_platform(&VmGuestPlatform::Windows)
                .unwrap(),
            vec![RoleCapability::Client, RoleCapability::EntryRelay]
        );
    }
}
