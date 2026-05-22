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
