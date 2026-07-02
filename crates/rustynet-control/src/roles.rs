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
    // New variants append at the end only: the derived ordering
    // feeds `canonicalize_role_capabilities` and therefore the
    // canonical signed pre-image. Reordering existing variants
    // would silently change signed payloads.
    ServesNas,
    ServesLlm,
    /// Selection PREFERENCE for the Pin-then-Seniority port-mapping
    /// authority comparator (`gossip_runtime::select_port_mapping_authority_node_id`).
    /// Only takes effect on a node that independently passes the
    /// `AnchorPortMappingAuthoritative` eligibility filter; validated
    /// in `validate_membership_node_capabilities`.
    AnchorPortMappingPinned,
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
            RoleCapability::ServesNas => "serves_nas",
            RoleCapability::ServesLlm => "serves_llm",
            RoleCapability::AnchorPortMappingPinned => "anchor.port_mapping_pinned",
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
            "serves_nas" | "serves-nas" => Ok(RoleCapability::ServesNas),
            "serves_llm" | "serves-llm" => Ok(RoleCapability::ServesLlm),
            "anchor.port_mapping_pinned" | "port_mapping_pinned" | "port-mapping-pinned" => {
                Ok(RoleCapability::AnchorPortMappingPinned)
            }
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
                | RoleCapability::AnchorPortMappingPinned
        )
    }

    /// Whether this is a service-hosting capability (the node
    /// co-runs an application-layer sibling service exposed
    /// tunnel-only under default-deny signed policy). See
    /// `NodeRoleTaxonomyExtension_2026-06-11.md`.
    pub fn is_service_hosting_capability(self) -> bool {
        matches!(self, RoleCapability::ServesNas | RoleCapability::ServesLlm)
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

    const ALL_CAPABILITIES: [RoleCapability; 14] = [
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
        RoleCapability::ServesNas,
        RoleCapability::ServesLlm,
        RoleCapability::AnchorPortMappingPinned,
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
            ("serves-nas", RoleCapability::ServesNas),
            ("serves-llm", RoleCapability::ServesLlm),
        ];

        for (input, expected) in cases {
            assert_eq!(RoleCapability::parse(input), Ok(expected));
        }
    }

    #[test]
    fn service_hosting_capability_predicate() {
        assert!(RoleCapability::ServesNas.is_service_hosting_capability());
        assert!(RoleCapability::ServesLlm.is_service_hosting_capability());
        for capability in ALL_CAPABILITIES {
            if capability != RoleCapability::ServesNas && capability != RoleCapability::ServesLlm {
                assert!(
                    !capability.is_service_hosting_capability(),
                    "{capability} must not be service-hosting"
                );
            }
        }
    }

    #[test]
    fn service_hosting_capabilities_sort_after_existing_variants() {
        // Canonical signed pre-images sort capabilities by the
        // derived ordering; the new variants must append after every
        // pre-existing one so historical canonical payloads are
        // unchanged.
        for capability in ALL_CAPABILITIES {
            if capability == RoleCapability::ServesNas
                || capability == RoleCapability::ServesLlm
                || capability == RoleCapability::AnchorPortMappingPinned
            {
                continue;
            }
            assert!(capability < RoleCapability::ServesNas);
        }
        assert!(RoleCapability::ServesNas < RoleCapability::ServesLlm);
        assert!(RoleCapability::ServesLlm < RoleCapability::AnchorPortMappingPinned);
        assert_eq!(
            role_capability_csv(&[
                RoleCapability::ServesLlm,
                RoleCapability::Anchor,
                RoleCapability::ServesNas,
            ]),
            "anchor,serves_nas,serves_llm"
        );
    }

    #[test]
    fn role_capability_pinned_round_trips_canonical_and_aliases() {
        assert_eq!(
            RoleCapability::AnchorPortMappingPinned.as_str(),
            "anchor.port_mapping_pinned"
        );
        for alias in [
            "anchor.port_mapping_pinned",
            "port_mapping_pinned",
            "port-mapping-pinned",
        ] {
            assert_eq!(
                RoleCapability::parse(alias),
                Ok(RoleCapability::AnchorPortMappingPinned)
            );
        }
        assert!(RoleCapability::AnchorPortMappingPinned.is_anchor_capability());
        // The pin is a selection preference, not a grant: the legacy
        // "anchor" role token must never auto-grant it.
        assert!(!ANCHOR_CAPABILITIES.contains(&RoleCapability::AnchorPortMappingPinned));
        assert!(!anchor_role_capabilities().contains(&RoleCapability::AnchorPortMappingPinned));
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
