#![allow(dead_code)]
use std::fmt;

use crate::vm_lab::VmGuestPlatform;

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
    /// Windows/macOS Exit remains fail-closed until W5.4 live evidence is recorded.
    ///
    /// | Role   | Linux | Windows | macOS | iOS | Android |
    /// |--------|-------|---------|-------|-----|---------|
    /// | Exit   | ✓     | ✗       | ✗     | ✗   | ✗       |
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
            VmGuestPlatform::Linux => true,
            VmGuestPlatform::Windows | VmGuestPlatform::Macos => !self.is_membership_owner(),
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
                        return Err("custom role label must not be empty".to_string());
                    }
                    Ok(NodeRole::Custom(label.to_string()))
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
        assert!(!NodeRole::Custom("foo".to_string()).is_unique_per_lab());
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
            NodeRole::Custom("foo".to_string())
        );
        assert_eq!(
            NodeRole::parse("custom-relay-test").unwrap(),
            NodeRole::Custom("relay-test".to_string())
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
    fn is_supported_for_platform_windows_macos_fail_closed_for_exit_only() {
        for platform in &[VmGuestPlatform::Windows, VmGuestPlatform::Macos] {
            assert!(
                !NodeRole::Exit.is_supported_for_platform(platform),
                "Exit must remain fail-closed on {platform:?} until W5.4 live evidence exists"
            );
            for role in &[
                NodeRole::Client,
                NodeRole::Entry,
                NodeRole::Aux,
                NodeRole::Extra,
            ] {
                assert!(
                    role.is_supported_for_platform(platform),
                    "{role:?} must be supported on {platform:?}"
                );
            }
        }
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
}
