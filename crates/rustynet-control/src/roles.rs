#![forbid(unsafe_code)]

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RoleCapability {
    Anchor,
    Client,
    ExitServer,
    BlindExit,
    RelayHost,
    EntryRelay,
    AnchorGossipSeed,
    AnchorBundlePull,
    AnchorEnrollmentEndpoint,
    AnchorRelayColocation,
    AnchorPortMappingAuthoritative,
}

impl RoleCapability {
    pub fn as_str(self) -> &'static str {
        match self {
            RoleCapability::Anchor => "anchor",
            RoleCapability::Client => "client",
            RoleCapability::ExitServer => "exit_server",
            RoleCapability::BlindExit => "blind_exit",
            RoleCapability::RelayHost => "relay_host",
            RoleCapability::EntryRelay => "entry_relay",
            RoleCapability::AnchorGossipSeed => "anchor.gossip_seed",
            RoleCapability::AnchorBundlePull => "anchor.bundle_pull",
            RoleCapability::AnchorEnrollmentEndpoint => "anchor.enrollment_endpoint",
            RoleCapability::AnchorRelayColocation => "anchor.relay_colocation",
            RoleCapability::AnchorPortMappingAuthoritative => "anchor.port_mapping_authoritative",
        }
    }

    pub fn parse(value: &str) -> Result<Self, RoleCapabilityParseError> {
        match value.trim() {
            "anchor" => Ok(RoleCapability::Anchor),
            "client" => Ok(RoleCapability::Client),
            "exit_server" | "exit-server" => Ok(RoleCapability::ExitServer),
            "blind_exit" | "blind-exit" => Ok(RoleCapability::BlindExit),
            "relay_host" | "relay-host" => Ok(RoleCapability::RelayHost),
            "entry_relay" | "entry-relay" => Ok(RoleCapability::EntryRelay),
            "anchor.gossip_seed" | "gossip_seed" | "gossip-seed" => {
                Ok(RoleCapability::AnchorGossipSeed)
            }
            "anchor.bundle_pull" | "bundle_pull" | "bundle-pull" => {
                Ok(RoleCapability::AnchorBundlePull)
            }
            "anchor.enrollment_endpoint" | "enrollment_endpoint" | "enrollment-endpoint" => {
                Ok(RoleCapability::AnchorEnrollmentEndpoint)
            }
            "anchor.relay_colocation" | "relay_colocation" | "relay-colocation" => {
                Ok(RoleCapability::AnchorRelayColocation)
            }
            "anchor.port_mapping_authoritative"
            | "port_mapping_authoritative"
            | "port-mapping-authoritative" => Ok(RoleCapability::AnchorPortMappingAuthoritative),
            "" => Err(RoleCapabilityParseError::Empty),
            other => Err(RoleCapabilityParseError::Unknown(other.to_owned())),
        }
    }

    pub fn is_anchor_capability(self) -> bool {
        matches!(
            self,
            RoleCapability::AnchorGossipSeed
                | RoleCapability::AnchorBundlePull
                | RoleCapability::AnchorEnrollmentEndpoint
                | RoleCapability::AnchorRelayColocation
                | RoleCapability::AnchorPortMappingAuthoritative
        )
    }
}

pub const ANCHOR_CAPABILITIES: [RoleCapability; 5] = [
    RoleCapability::AnchorGossipSeed,
    RoleCapability::AnchorBundlePull,
    RoleCapability::AnchorEnrollmentEndpoint,
    RoleCapability::AnchorRelayColocation,
    RoleCapability::AnchorPortMappingAuthoritative,
];

pub fn anchor_role_capabilities() -> Vec<RoleCapability> {
    let mut capabilities = Vec::with_capacity(ANCHOR_CAPABILITIES.len() + 2);
    capabilities.push(RoleCapability::Anchor);
    capabilities.push(RoleCapability::RelayHost);
    capabilities.extend(ANCHOR_CAPABILITIES);
    canonicalize_role_capabilities(capabilities)
}

impl fmt::Display for RoleCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleCapabilityParseError {
    Empty,
    Unknown(String),
}

impl fmt::Display for RoleCapabilityParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RoleCapabilityParseError::Empty => f.write_str("role capability must not be empty"),
            RoleCapabilityParseError::Unknown(value) => {
                write!(f, "unknown role capability {value}")
            }
        }
    }
}

impl std::error::Error for RoleCapabilityParseError {}

pub fn canonicalize_role_capabilities(
    capabilities: impl IntoIterator<Item = RoleCapability>,
) -> Vec<RoleCapability> {
    let mut capabilities = capabilities.into_iter().collect::<Vec<_>>();
    capabilities.sort_unstable();
    capabilities.dedup();
    capabilities
}

pub fn parse_role_capability_csv(
    value: &str,
) -> Result<Vec<RoleCapability>, RoleCapabilityParseError> {
    let mut parsed = Vec::new();
    for item in value.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        parsed.push(RoleCapability::parse(item)?);
    }
    Ok(canonicalize_role_capabilities(parsed))
}

pub fn role_capability_csv(capabilities: &[RoleCapability]) -> String {
    canonicalize_role_capabilities(capabilities.iter().copied())
        .into_iter()
        .map(RoleCapability::as_str)
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_CAPABILITIES: [RoleCapability; 11] = [
        RoleCapability::Anchor,
        RoleCapability::Client,
        RoleCapability::ExitServer,
        RoleCapability::BlindExit,
        RoleCapability::RelayHost,
        RoleCapability::EntryRelay,
        RoleCapability::AnchorGossipSeed,
        RoleCapability::AnchorBundlePull,
        RoleCapability::AnchorEnrollmentEndpoint,
        RoleCapability::AnchorRelayColocation,
        RoleCapability::AnchorPortMappingAuthoritative,
    ];

    #[test]
    fn role_capability_parse_accepts_canonical_names() {
        for capability in ALL_CAPABILITIES {
            assert_eq!(RoleCapability::parse(capability.as_str()), Ok(capability));
        }
    }

    #[test]
    fn role_capability_parse_accepts_documented_aliases() {
        let cases = [
            ("exit-server", RoleCapability::ExitServer),
            ("blind-exit", RoleCapability::BlindExit),
            ("relay-host", RoleCapability::RelayHost),
            ("entry-relay", RoleCapability::EntryRelay),
            ("gossip_seed", RoleCapability::AnchorGossipSeed),
            ("gossip-seed", RoleCapability::AnchorGossipSeed),
            ("bundle_pull", RoleCapability::AnchorBundlePull),
            ("bundle-pull", RoleCapability::AnchorBundlePull),
            (
                "enrollment_endpoint",
                RoleCapability::AnchorEnrollmentEndpoint,
            ),
            (
                "enrollment-endpoint",
                RoleCapability::AnchorEnrollmentEndpoint,
            ),
            ("relay_colocation", RoleCapability::AnchorRelayColocation),
            ("relay-colocation", RoleCapability::AnchorRelayColocation),
            (
                "port_mapping_authoritative",
                RoleCapability::AnchorPortMappingAuthoritative,
            ),
            (
                "port-mapping-authoritative",
                RoleCapability::AnchorPortMappingAuthoritative,
            ),
        ];

        for (input, expected) in cases {
            assert_eq!(RoleCapability::parse(input), Ok(expected));
        }
    }

    #[test]
    fn role_capability_parse_rejects_empty_whitespace_and_unknown() {
        assert_eq!(
            RoleCapability::parse(""),
            Err(RoleCapabilityParseError::Empty)
        );
        assert_eq!(
            RoleCapability::parse(" \t\n "),
            Err(RoleCapabilityParseError::Empty)
        );
        assert_eq!(
            RoleCapability::parse("owner"),
            Err(RoleCapabilityParseError::Unknown("owner".to_string()))
        );
    }

    #[test]
    fn parse_role_capability_csv_trims_deduplicates_and_sorts() {
        let parsed = parse_role_capability_csv(" relay_host,client, relay-host ,anchor ")
            .expect("valid csv parses");

        assert_eq!(
            parsed,
            vec![
                RoleCapability::Anchor,
                RoleCapability::Client,
                RoleCapability::RelayHost,
            ]
        );
    }

    #[test]
    fn parse_role_capability_csv_handles_empty_and_trailing_commas() {
        assert_eq!(
            parse_role_capability_csv("").expect("empty csv parses"),
            vec![]
        );
        assert_eq!(
            parse_role_capability_csv(" , , ").expect("whitespace csv parses"),
            vec![]
        );
        assert_eq!(
            parse_role_capability_csv("client,").expect("trailing comma parses"),
            vec![RoleCapability::Client]
        );
    }

    #[test]
    fn parse_role_capability_csv_rejects_mixed_invalid_items() {
        assert_eq!(
            parse_role_capability_csv("client,unknown"),
            Err(RoleCapabilityParseError::Unknown("unknown".to_string()))
        );
    }

    #[test]
    fn canonicalize_role_capabilities_is_deduping_and_idempotent() {
        let once = canonicalize_role_capabilities([
            RoleCapability::Client,
            RoleCapability::Anchor,
            RoleCapability::Client,
            RoleCapability::AnchorBundlePull,
        ]);
        let twice = canonicalize_role_capabilities(once.iter().copied());

        assert_eq!(once, twice);
        assert_eq!(
            once,
            vec![
                RoleCapability::Anchor,
                RoleCapability::Client,
                RoleCapability::AnchorBundlePull,
            ]
        );
    }

    #[test]
    fn anchor_role_capabilities_contains_role_relay_and_all_anchor_subcaps() {
        let capabilities = anchor_role_capabilities();

        assert!(capabilities.contains(&RoleCapability::Anchor));
        assert!(capabilities.contains(&RoleCapability::RelayHost));
        for capability in ANCHOR_CAPABILITIES {
            assert!(capabilities.contains(&capability));
            assert!(capability.is_anchor_capability());
        }
        assert_eq!(capabilities.len(), ANCHOR_CAPABILITIES.len() + 2);
    }

    #[test]
    fn role_capability_csv_uses_canonical_names_in_stable_order() {
        assert_eq!(
            role_capability_csv(&[
                RoleCapability::RelayHost,
                RoleCapability::Anchor,
                RoleCapability::RelayHost,
                RoleCapability::AnchorBundlePull,
            ]),
            "anchor,relay_host,anchor.bundle_pull"
        );
    }
}
