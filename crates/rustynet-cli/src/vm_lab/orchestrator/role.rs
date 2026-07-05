#![allow(dead_code)]
use std::fmt;

use crate::vm_lab::VmGuestPlatform;
use rustynet_control::roles::RoleCapability;
use serde::{Deserialize, Serialize};

/// OS-agnostic role definition. The 5 named roles match the bash
/// orchestrator's existing names so membership / traffic-test / role-switch
/// logic stays semantically identical.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeRole {
    Exit,
    Anchor,
    Relay,
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
    /// macOS Exit maps to the reviewed `blind_exit` PF posture. Anchor and
    /// Relay are supported on Linux today (live-evidenced) and remain
    /// fail-closed on macOS + Windows until a green standard-orchestrator run
    /// is archived (cross-OS role-testing Phase 8); they are still
    /// lab-assignable everywhere so that evidence can be generated.
    ///
    /// | Role   | Linux | Windows | macOS | iOS | Android |
    /// |--------|-------|---------|-------|-----|---------|
    /// | Exit   | ✓     | ✗       | ✓     | ✗   | ✗       |
    /// | Anchor | ✓     | ✗       | ✗     | ✗   | ✗       |
    /// | Relay  | ✓     | ✗       | ✗     | ✗   | ✗       |
    /// | Client | ✓     | ✓       | ✓     | ✗   | ✗       |
    /// | Entry  | ✓     | ✓       | ✓     | ✗   | ✗       |
    /// | Aux    | ✓     | ✓       | ✓     | ✗   | ✗       |
    /// | Extra  | ✓     | ✓       | ✓     | ✗   | ✗       |
    ///
    /// iOS and Android adapters fail closed with security-specific rejection
    /// messages (unreviewed key custody + connection model + daemon coverage).
    pub fn is_supported_for_platform(&self, platform: &VmGuestPlatform) -> bool {
        match self {
            // New cross-OS control-plane roles: live evidence exists on Linux
            // today. macOS + Windows are lab-assignable for evidence
            // generation (see `is_lab_assignable_for_platform`) and are
            // promoted to supported here only once a green run is archived,
            // mirroring the Windows-Exit posture-promotion gate. Strictest
            // secure default until then: fail closed.
            NodeRole::Anchor | NodeRole::Relay => matches!(platform, VmGuestPlatform::Linux),
            _ => match platform {
                VmGuestPlatform::Ios | VmGuestPlatform::Android => false,
                VmGuestPlatform::Linux | VmGuestPlatform::Macos => true,
                VmGuestPlatform::Windows => !self.is_membership_owner(),
            },
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
            NodeRole::Anchor => "anchor",
            NodeRole::Relay => "relay",
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
                // Anchor runs as the `admin` daemon role: it holds the `anchor`
                // capability the daemon's admin role requires and serves the
                // control plane. Relay runs as the `client` daemon role — it is
                // a client that ALSO hosts a relay (relay_host, via a separate
                // rustynet-relay service). The daemon's admin role requires the
                // `anchor` capability (membership.rs role↔capability alignment),
                // which a relay neither holds nor should; running a relay as
                // admin fail-closes reconcile ("admin requires anchor").
                NodeRole::Anchor => Ok("admin"),
                NodeRole::Client
                | NodeRole::Entry
                | NodeRole::Aux
                | NodeRole::Extra
                | NodeRole::Relay => Ok("client"),
                NodeRole::Custom(label) => Err(format!(
                    "custom lab role '{label}' has no explicit daemon role mapping"
                )),
            },
            VmGuestPlatform::Macos => match self {
                NodeRole::Exit => Ok("blind_exit"),
                // Anchor = admin (holds the `anchor` capability). Relay =
                // client + relay_host (see the Linux/Windows arm): admin would
                // fail-close reconcile because admin requires `anchor`.
                NodeRole::Anchor => Ok("admin"),
                NodeRole::Client
                | NodeRole::Entry
                | NodeRole::Aux
                | NodeRole::Extra
                | NodeRole::Relay => Ok("client"),
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
                // Anchor advertises the canonical anchor capability set: the
                // Anchor marker + relay_host + the five composable anchor
                // sub-capabilities, exactly matching
                // `rustynet_control::roles::anchor_role_capabilities()`.
                // relay_host is REQUIRED, not optional: anchors co-locate a
                // relay, and the daemon's membership-format validation rejects
                // `anchor.relay_colocation` without `relay_host`
                // (membership.rs `validate_membership_node_capabilities`). The
                // daemon + gossip / bundle-pull / enrollment / port-mapping
                // paths read these from the signed membership snapshot.
                // Platform-independent: the same set is advertised on every OS.
                NodeRole::Anchor => Ok(vec![
                    RoleCapability::Anchor,
                    RoleCapability::RelayHost,
                    RoleCapability::AnchorGossipSeed,
                    RoleCapability::AnchorBundlePull,
                    RoleCapability::AnchorEnrollmentEndpoint,
                    RoleCapability::AnchorRelayColocation,
                    RoleCapability::AnchorPortMappingAuthoritative,
                ]),
                // Relay is a relay-host that also participates as a client
                // peer (matches the `client,relay_host` capability CSV the
                // relay/anchor harnesses use as the downgrade/restore target).
                NodeRole::Relay => Ok(vec![RoleCapability::Client, RoleCapability::RelayHost]),
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
            "anchor" => Ok(NodeRole::Anchor),
            "relay" => Ok(NodeRole::Relay),
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
                        "unknown role '{other}'; expected one of: exit, anchor, relay, client, entry, aux, extra, custom-<label>"
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

    // ── Anchor + Relay: first-class cross-OS roles ──────────────────────────

    #[test]
    fn parse_anchor_and_relay_roles() {
        assert_eq!(NodeRole::parse("anchor").unwrap(), NodeRole::Anchor);
        assert_eq!(NodeRole::parse("relay").unwrap(), NodeRole::Relay);
        // Round-trips back to the same wire string.
        assert_eq!(NodeRole::Anchor.as_str(), "anchor");
        assert_eq!(NodeRole::Relay.as_str(), "relay");
    }

    #[test]
    fn anchor_relay_are_not_owners_and_not_unique() {
        // Multiple anchors/relays are valid (gossip-priority needs >=2
        // anchors); neither is the membership owner (Exit signs bundles).
        for role in [NodeRole::Anchor, NodeRole::Relay] {
            assert!(!role.is_unique_per_lab(), "{role:?} must not be unique");
            assert!(!role.is_membership_owner(), "{role:?} must not be owner");
        }
    }

    #[test]
    fn anchor_relay_lab_assignable_on_all_desktop_os() {
        // The lab gate (mod.rs) keys on is_lab_assignable_for_platform; anchor
        // and relay must be assignable on every desktop OS so cross-OS live
        // evidence can be generated.
        for role in [NodeRole::Anchor, NodeRole::Relay] {
            for platform in [
                VmGuestPlatform::Linux,
                VmGuestPlatform::Macos,
                VmGuestPlatform::Windows,
            ] {
                assert!(
                    role.is_lab_assignable_for_platform(&platform),
                    "{role:?} must be lab-assignable on {platform:?}"
                );
            }
            for platform in [VmGuestPlatform::Ios, VmGuestPlatform::Android] {
                assert!(
                    !role.is_lab_assignable_for_platform(&platform),
                    "{role:?} must not be lab-assignable on {platform:?}"
                );
            }
        }
    }

    #[test]
    fn anchor_relay_supported_on_linux_failclosed_elsewhere_until_evidence() {
        // Strictest-secure default: supported only where live evidence exists
        // (Linux today). macOS + Windows are fail-closed until a green
        // standard-orchestrator run is archived (Phase 8 promotes them),
        // mirroring the Windows-Exit posture gate.
        for role in [NodeRole::Anchor, NodeRole::Relay] {
            assert!(
                role.is_supported_for_platform(&VmGuestPlatform::Linux),
                "{role:?} is live-evidenced + supported on Linux"
            );
            for platform in [
                VmGuestPlatform::Macos,
                VmGuestPlatform::Windows,
                VmGuestPlatform::Ios,
                VmGuestPlatform::Android,
            ] {
                assert!(
                    !role.is_supported_for_platform(&platform),
                    "{role:?} must be fail-closed-unsupported on {platform:?} until evidence"
                );
            }
        }
    }

    #[test]
    fn anchor_is_admin_relay_is_client_daemon_role_on_every_os() {
        // Anchor holds the `anchor` capability → admin daemon role. Relay is a
        // client that hosts a relay (relay_host) → client daemon role; admin
        // would fail-close reconcile ("admin requires anchor"), which a live
        // run hit before this split. (A live combined run's membership/baseline
        // failed with this exact mismatch when relay mapped to admin.)
        for platform in [
            VmGuestPlatform::Linux,
            VmGuestPlatform::Macos,
            VmGuestPlatform::Windows,
        ] {
            assert_eq!(
                NodeRole::Anchor
                    .daemon_node_role_for_platform(&platform)
                    .unwrap(),
                "admin",
                "anchor on {platform:?} runs as the admin daemon role"
            );
            assert_eq!(
                NodeRole::Relay
                    .daemon_node_role_for_platform(&platform)
                    .unwrap(),
                "client",
                "relay on {platform:?} runs as the client daemon role"
            );
        }
    }

    #[test]
    fn anchor_capabilities_include_relay_host_and_the_five_subcaps() {
        // relay_host is REQUIRED alongside the anchor sub-caps: the daemon's
        // membership-format validation rejects anchor.relay_colocation without
        // relay_host (a live membership_init failed exactly this way before
        // relay_host was added here). Matches the set of
        // rustynet_control::roles::anchor_role_capabilities().
        let expected = vec![
            RoleCapability::Anchor,
            RoleCapability::RelayHost,
            RoleCapability::AnchorGossipSeed,
            RoleCapability::AnchorBundlePull,
            RoleCapability::AnchorEnrollmentEndpoint,
            RoleCapability::AnchorRelayColocation,
            RoleCapability::AnchorPortMappingAuthoritative,
        ];
        for platform in [
            VmGuestPlatform::Linux,
            VmGuestPlatform::Macos,
            VmGuestPlatform::Windows,
        ] {
            let caps = NodeRole::Anchor
                .product_capabilities_for_platform(&platform)
                .unwrap();
            assert_eq!(
                caps, expected,
                "anchor advertises the full set on {platform:?}"
            );
            // Daemon invariant: relay_colocation implies relay_host.
            assert!(
                caps.contains(&RoleCapability::AnchorRelayColocation)
                    && caps.contains(&RoleCapability::RelayHost),
                "anchor.relay_colocation requires relay_host on {platform:?}"
            );
        }
    }

    #[test]
    fn relay_capabilities_are_client_plus_relay_host() {
        for platform in [
            VmGuestPlatform::Linux,
            VmGuestPlatform::Macos,
            VmGuestPlatform::Windows,
        ] {
            assert_eq!(
                NodeRole::Relay
                    .product_capabilities_for_platform(&platform)
                    .unwrap(),
                vec![RoleCapability::Client, RoleCapability::RelayHost],
                "relay advertises client+relay_host on {platform:?}"
            );
        }
    }
}
