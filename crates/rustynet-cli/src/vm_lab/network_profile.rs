//! Typed network-profile model for the live-lab VM connectivity rulebook
//! (`documents/operations/LiveLabVmConnectivityRulebook.md` §15).
//!
//! Slice A read-only foundation: strict manifest parsing, canonical profile
//! digests, the backend capability matrix, and address-plan validation. This
//! module performs no VM, UTM, inventory, or host mutation. Every parse or
//! validation failure is fail-closed: the profile is rejected, never repaired.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Maximum accepted manifest size. Profiles are small reviewed documents; an
/// oversized file is rejected rather than best-effort parsed.
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_DESCRIPTION_CHARS: usize = 500;
const MAX_PHYSICAL_INTERFACES: usize = 8;
const SUPPORTED_SCHEMA_VERSION: u32 = 1;

/// Rustynet mesh overlay range (RFC 6598). Underlay use of this range is
/// restricted to explicit CGNAT collision profiles.
pub const MESH_OVERLAY_CIDR: &str = "100.64.0.0/10";
/// Canonical ordinary simulated-internet/transit range (IANA benchmarking).
pub const CANONICAL_TRANSIT_CIDR: &str = "198.18.0.0/15";
/// Canonical scenario site pool; one subnet per site is carved from here.
pub const CANONICAL_SITE_POOL_CIDR: &str = "172.20.0.0/16";
/// The host interface that is never allowed in a physical profile allowlist.
pub const FORBIDDEN_PHYSICAL_INTERFACE: &str = "en0";

/// External run/stage status vocabulary (rulebook §15.5). `skipped` is
/// intentionally absent: it is internal scheduling state only and must resolve
/// to one of these before evidence is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkEvidenceStatus {
    Pass,
    Fail,
    NotRun,
    NotSupported,
    /// Adversarial behavior failed in the exact fail-closed manner declared
    /// before execution. Constructed by stage integration (Slice C); declared
    /// from Slice A so the external vocabulary is complete and stable.
    #[allow(dead_code)]
    ExpectedFail,
}

impl NetworkEvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::NotRun => "not_run",
            Self::NotSupported => "not_supported",
            Self::ExpectedFail => "expected_fail",
        }
    }
}

impl fmt::Display for NetworkEvidenceStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Validated profile identifier: `[a-z0-9_]{3,64}`, must match the manifest
/// filename stem.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct NetworkProfileId(String);

impl NetworkProfileId {
    pub fn parse(raw: &str) -> Result<Self, String> {
        if raw.len() < 3 || raw.len() > 64 {
            return Err(format!(
                "network profile id must be 3-64 characters, got {} ({raw:?})",
                raw.len()
            ));
        }
        if !raw
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        {
            return Err(format!(
                "network profile id may contain only [a-z0-9_]: {raw:?}"
            ));
        }
        Ok(Self(raw.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NetworkProfileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// UTM configuration backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UtmBackend {
    Qemu,
    Apple,
}

impl UtmBackend {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "QEMU" => Ok(Self::Qemu),
            "Apple" => Ok(Self::Apple),
            other => Err(format!("unsupported UTM backend {other:?}")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Qemu => "qemu",
            Self::Apple => "apple",
        }
    }
}

/// Observed per-NIC attachment mode as reported by a UTM `config.plist`.
/// `Deserialize` is derived for the transaction journal roundtrip; unknown
/// values fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentMode {
    Shared,
    HostOnly,
    Bridged,
    Emulated,
    Disconnected,
}

impl AttachmentMode {
    /// Parse the `Mode` string from a UTM config for the given backend.
    /// Unknown modes fail closed.
    pub fn parse_utm(raw: &str, backend: UtmBackend) -> Result<Self, String> {
        match (raw, backend) {
            ("Shared", _) => Ok(Self::Shared),
            ("Host", UtmBackend::Qemu) => Ok(Self::HostOnly),
            ("Bridged", _) => Ok(Self::Bridged),
            ("Emulated", UtmBackend::Qemu) => Ok(Self::Emulated),
            ("None", UtmBackend::Qemu) => Ok(Self::Disconnected),
            (other, backend) => Err(format!(
                "unsupported UTM network mode {other:?} for backend {}",
                backend.as_str()
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Shared => "shared",
            Self::HostOnly => "host_only",
            Self::Bridged => "bridged",
            Self::Emulated => "emulated",
            Self::Disconnected => "disconnected",
        }
    }
}

impl fmt::Display for AttachmentMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Backend capability verdict for the capability matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilitySupport {
    Supported,
    NotSupported,
    /// The vendor API documents support but the lab has not live-proven it
    /// (rulebook §15.9 owner decision 5). Treated as unavailable for
    /// fail-closed decisions until proven.
    Unproven,
}

impl CapabilitySupport {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::NotSupported => "not_supported",
            Self::Unproven => "unproven",
        }
    }
}

/// Backend capability matrix (rulebook §4.1/§5). Static, conservative facts
/// about what each UTM backend can attach.
pub fn backend_attachment_support(backend: UtmBackend, mode: AttachmentMode) -> CapabilitySupport {
    match (backend, mode) {
        (UtmBackend::Qemu, _) => CapabilitySupport::Supported,
        (UtmBackend::Apple, AttachmentMode::Shared | AttachmentMode::Bridged) => {
            CapabilitySupport::Supported
        }
        (UtmBackend::Apple, _) => CapabilitySupport::NotSupported,
    }
}

/// Multi-NIC (dual-plane) support per backend. Apple's Virtualization
/// framework documents multiple NICs but UTM behavior is not yet live-proven
/// in this lab, so it reports `Unproven` and fails closed.
pub fn backend_multi_nic_support(backend: UtmBackend) -> CapabilitySupport {
    match backend {
        UtmBackend::Qemu => CapabilitySupport::Supported,
        UtmBackend::Apple => CapabilitySupport::Unproven,
    }
}

/// Management-NIC attachment policy (rulebook §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagementAttachmentPolicy {
    Shared,
    HostOnly,
    HostOnlyOrShared,
}

impl ManagementAttachmentPolicy {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "shared" => Ok(Self::Shared),
            "host_only" => Ok(Self::HostOnly),
            "host_only_or_shared" => Ok(Self::HostOnlyOrShared),
            other => Err(format!(
                "unsupported management attachment {other:?} (expected shared | host_only | host_only_or_shared)"
            )),
        }
    }

    /// Whether an observed attachment satisfies this policy.
    pub fn permits(self, observed: AttachmentMode) -> bool {
        match self {
            Self::Shared => observed == AttachmentMode::Shared,
            Self::HostOnly => observed == AttachmentMode::HostOnly,
            Self::HostOnlyOrShared => {
                matches!(observed, AttachmentMode::Shared | AttachmentMode::HostOnly)
            }
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Shared => "shared",
            Self::HostOnly => "host_only",
            Self::HostOnlyOrShared => "host_only_or_shared",
        }
    }
}

/// Management-plane security mode (rulebook §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagementSecurityMode {
    /// Ordinary dual-NIC operation; not valid single-homed leak proof.
    Routine,
    /// Host /32 route + SSH allow only; no gateway or DNS.
    Quarantined,
    /// Guest agent / serial / hypervisor control; no in-band management NIC.
    OutOfBand,
    /// Management NIC brought down for the security stage.
    LinkDown,
}

impl ManagementSecurityMode {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "routine" => Ok(Self::Routine),
            "quarantined" => Ok(Self::Quarantined),
            "out_of_band" => Ok(Self::OutOfBand),
            "link_down" => Ok(Self::LinkDown),
            other => Err(format!(
                "unsupported management security mode {other:?} (expected routine | quarantined | out_of_band | link_down)"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Routine => "routine",
            Self::Quarantined => "quarantined",
            Self::OutOfBand => "out_of_band",
            Self::LinkDown => "link_down",
        }
    }
}

/// Scenario-plane substrate (rulebook §4.2/§5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioSubstrate {
    /// No scenario plane: management-only profile with no network claim.
    None,
    IsolatedLan,
    Vxlan,
    Netns,
    /// Bridged to a dedicated, explicitly allowlisted physical interface.
    PhysicalInterface,
    RemotePhysical,
}

impl ScenarioSubstrate {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "none" => Ok(Self::None),
            "isolated_lan" => Ok(Self::IsolatedLan),
            "vxlan" => Ok(Self::Vxlan),
            "netns" => Ok(Self::Netns),
            "physical_interface" => Ok(Self::PhysicalInterface),
            "remote_physical" => Ok(Self::RemotePhysical),
            other => Err(format!(
                "unsupported scenario substrate {other:?} (expected none | isolated_lan | vxlan | netns | physical_interface | remote_physical)"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::IsolatedLan => "isolated_lan",
            Self::Vxlan => "vxlan",
            Self::Netns => "netns",
            Self::PhysicalInterface => "physical_interface",
            Self::RemotePhysical => "remote_physical",
        }
    }
}

/// Scenario address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressFamily {
    V4Only,
    V6Only,
    DualStack,
}

impl AddressFamily {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "v4_only" => Ok(Self::V4Only),
            "v6_only" => Ok(Self::V6Only),
            "dual_stack" => Ok(Self::DualStack),
            other => Err(format!(
                "unsupported address family {other:?} (expected v4_only | v6_only | dual_stack)"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::V4Only => "v4_only",
            Self::V6Only => "v6_only",
            Self::DualStack => "dual_stack",
        }
    }
}

/// Scenario internet policy (rulebook §9). Internet is not one boolean.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InternetMode {
    None,
    /// Deterministic lab-owned internet-in-a-box.
    Simulated,
    /// Declared lab-router public egress; never a hidden host proxy.
    ControlledPublic,
}

impl InternetMode {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "none" => Ok(Self::None),
            "simulated" => Ok(Self::Simulated),
            "controlled_public" => Ok(Self::ControlledPublic),
            other => Err(format!(
                "unsupported internet mode {other:?} (expected none | simulated | controlled_public)"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Simulated => "simulated",
            Self::ControlledPublic => "controlled_public",
        }
    }
}

/// Evidence tier of the canonical test ladder (rulebook §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceTier {
    /// Build/install iteration; no network claim.
    ManagementOnly,
    /// Tier 1: deterministic Linux netns NAT/security regression.
    Netns,
    /// Tier 2: isolated multi-VM (same-LAN or VXLAN sites).
    MultiVm,
    /// Tier 3: dedicated physical lab interface/router.
    PhysicalLab,
    /// Tier 4: genuinely distinct remote networks.
    RemoteWild,
}

impl EvidenceTier {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "management_only" => Ok(Self::ManagementOnly),
            "netns" => Ok(Self::Netns),
            "multi_vm" => Ok(Self::MultiVm),
            "physical_lab" => Ok(Self::PhysicalLab),
            "remote_wild" => Ok(Self::RemoteWild),
            other => Err(format!(
                "unsupported evidence tier {other:?} (expected management_only | netns | multi_vm | physical_lab | remote_wild)"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ManagementOnly => "management_only",
            Self::Netns => "netns",
            Self::MultiVm => "multi_vm",
            Self::PhysicalLab => "physical_lab",
            Self::RemoteWild => "remote_wild",
        }
    }
}

/// Validated management-plane policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManagementPolicy {
    pub attachment: ManagementAttachmentPolicy,
    pub internet: bool,
    pub peer_to_peer: bool,
    pub security_mode: ManagementSecurityMode,
}

/// Validated scenario-plane policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScenarioPolicy {
    pub substrate: ScenarioSubstrate,
    pub address_family: AddressFamily,
    pub internet_mode: InternetMode,
    pub require_unique_site_subnets: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site_subnet_pool: Option<IpCidr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site_prefix_len: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transit_subnet: Option<IpCidr>,
    pub allow_cgnat_underlay_collision: bool,
    pub requires_dedicated_oracle: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub physical: Option<PhysicalScenarioPolicy>,
}

/// Physical-interface allowlist for `physical_interface` substrates. `en0`
/// (the host's everyday LAN) is rejected unconditionally in Slice A; only an
/// owner decision may ever change that (rulebook §15.9 decision 3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PhysicalScenarioPolicy {
    pub allowed_host_interfaces: Vec<String>,
}

/// Validated evidence requirements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvidencePolicy {
    pub require_endpoint_capture: bool,
    pub require_router_capture: bool,
    pub require_negative_reachability: bool,
    pub forbid_socks_proxy: bool,
}

/// A fully validated network profile. Construction is only possible through
/// [`parse_network_profile_toml`]; the canonical digest is computed over this
/// validated representation, not raw TOML formatting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetworkProfile {
    pub schema_version: u32,
    pub id: NetworkProfileId,
    pub evidence_tier: EvidenceTier,
    pub description: String,
    pub management: ManagementPolicy,
    pub scenario: ScenarioPolicy,
    pub evidence: EvidencePolicy,
}

impl NetworkProfile {
    /// Canonical digest over the validated representation. Formatting-only
    /// changes to the manifest do not change the digest; any semantic change
    /// does.
    pub fn canonical_digest(&self) -> String {
        let canonical =
            serde_json::to_string(self).expect("validated network profile always serializes");
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        format!("sha256:{:x}", hasher.finalize())
    }

    /// Backend compatibility check (fail-closed). Returns `Err` with the
    /// blocking reason when a backend cannot satisfy this profile.
    pub fn backend_compatibility(&self, backend: UtmBackend) -> Result<(), String> {
        let management_modes: &[AttachmentMode] = match self.management.attachment {
            ManagementAttachmentPolicy::Shared => &[AttachmentMode::Shared],
            ManagementAttachmentPolicy::HostOnly => &[AttachmentMode::HostOnly],
            ManagementAttachmentPolicy::HostOnlyOrShared => {
                &[AttachmentMode::HostOnly, AttachmentMode::Shared]
            }
        };
        if !management_modes
            .iter()
            .any(|mode| backend_attachment_support(backend, *mode) == CapabilitySupport::Supported)
        {
            return Err(format!(
                "backend {} supports none of the management attachments required by profile {}",
                backend.as_str(),
                self.id
            ));
        }
        // A scenario plane on the same VM implies a second NIC.
        if self.scenario.substrate != ScenarioSubstrate::None {
            let multi_nic = backend_multi_nic_support(backend);
            if multi_nic != CapabilitySupport::Supported
                && self.scenario.substrate != ScenarioSubstrate::Netns
            {
                return Err(format!(
                    "backend {} multi-NIC support is {} but profile {} requires a scenario NIC",
                    backend.as_str(),
                    multi_nic.as_str(),
                    self.id
                ));
            }
        }
        if self.scenario.substrate == ScenarioSubstrate::PhysicalInterface
            && backend_attachment_support(backend, AttachmentMode::Bridged)
                != CapabilitySupport::Supported
        {
            return Err(format!(
                "backend {} cannot bridge to a physical interface for profile {}",
                backend.as_str(),
                self.id
            ));
        }
        Ok(())
    }
}

/// Strictly typed IPv4/IPv6 CIDR with exact overlap math.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpCidr {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

impl IpCidr {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let (addr_part, prefix_part) = raw
            .split_once('/')
            .ok_or_else(|| format!("CIDR {raw:?} is missing a /prefix"))?;
        let prefix: u8 = prefix_part
            .parse()
            .map_err(|_| format!("CIDR {raw:?} has a non-numeric prefix"))?;
        if let Ok(v4) = addr_part.parse::<Ipv4Addr>() {
            if prefix > 32 {
                return Err(format!("IPv4 CIDR {raw:?} prefix exceeds 32"));
            }
            let bits = u32::from(v4);
            let mask = v4_mask(prefix);
            if bits & !mask != 0 {
                return Err(format!(
                    "CIDR {raw:?} has host bits set; expected the network address"
                ));
            }
            return Ok(Self::V4 {
                network: bits,
                prefix,
            });
        }
        if let Ok(v6) = addr_part.parse::<Ipv6Addr>() {
            if prefix > 128 {
                return Err(format!("IPv6 CIDR {raw:?} prefix exceeds 128"));
            }
            let bits = u128::from(v6);
            let mask = v6_mask(prefix);
            if bits & !mask != 0 {
                return Err(format!(
                    "CIDR {raw:?} has host bits set; expected the network address"
                ));
            }
            return Ok(Self::V6 {
                network: bits,
                prefix,
            });
        }
        Err(format!("CIDR {raw:?} is not a valid IPv4 or IPv6 network"))
    }

    pub fn prefix(&self) -> u8 {
        match self {
            Self::V4 { prefix, .. } | Self::V6 { prefix, .. } => *prefix,
        }
    }

    /// True when the two networks share any address.
    pub fn overlaps(&self, other: &IpCidr) -> bool {
        match (self, other) {
            (
                Self::V4 {
                    network: a,
                    prefix: ap,
                },
                Self::V4 {
                    network: b,
                    prefix: bp,
                },
            ) => {
                let shared = (*ap).min(*bp);
                let mask = v4_mask(shared);
                a & mask == b & mask
            }
            (
                Self::V6 {
                    network: a,
                    prefix: ap,
                },
                Self::V6 {
                    network: b,
                    prefix: bp,
                },
            ) => {
                let shared = (*ap).min(*bp);
                let mask = v6_mask(shared);
                a & mask == b & mask
            }
            _ => false,
        }
    }

    /// True when `self` is entirely inside `outer`.
    pub fn is_within(&self, outer: &IpCidr) -> bool {
        match (self, outer) {
            (
                Self::V4 {
                    network: a,
                    prefix: ap,
                },
                Self::V4 {
                    network: b,
                    prefix: bp,
                },
            ) => ap >= bp && (a & v4_mask(*bp)) == *b,
            (
                Self::V6 {
                    network: a,
                    prefix: ap,
                },
                Self::V6 {
                    network: b,
                    prefix: bp,
                },
            ) => ap >= bp && (a & v6_mask(*bp)) == *b,
            _ => false,
        }
    }

    /// True when the single address falls inside this network.
    pub fn contains_v4(&self, addr: Ipv4Addr) -> bool {
        match self {
            Self::V4 { network, prefix } => u32::from(addr) & v4_mask(*prefix) == *network,
            Self::V6 { .. } => false,
        }
    }
}

impl fmt::Display for IpCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4 { network, prefix } => {
                write!(f, "{}/{prefix}", Ipv4Addr::from(*network))
            }
            Self::V6 { network, prefix } => {
                write!(f, "{}/{prefix}", Ipv6Addr::from(*network))
            }
        }
    }
}

impl Serialize for IpCidr {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

fn v4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    }
}

fn v6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix))
    }
}

/// The Rustynet mesh overlay range as a typed CIDR.
pub fn mesh_overlay_cidr() -> IpCidr {
    IpCidr::parse(MESH_OVERLAY_CIDR).expect("mesh overlay constant is valid")
}

// --- Raw manifest shapes (strict serde; unknown fields fail closed) ---

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    schema_version: u32,
    id: String,
    evidence_tier: String,
    description: String,
    management: RawManagement,
    scenario: RawScenario,
    evidence: RawEvidence,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManagement {
    attachment: String,
    internet: bool,
    peer_to_peer: bool,
    security_mode: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawScenario {
    substrate: String,
    address_family: String,
    internet_mode: String,
    require_unique_site_subnets: bool,
    #[serde(default)]
    site_subnet_pool: Option<String>,
    #[serde(default)]
    site_prefix_len: Option<u8>,
    #[serde(default)]
    transit_subnet: Option<String>,
    #[serde(default)]
    allow_cgnat_underlay_collision: bool,
    #[serde(default)]
    requires_dedicated_oracle: bool,
    #[serde(default)]
    physical: Option<RawPhysical>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPhysical {
    allowed_host_interfaces: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEvidence {
    require_endpoint_capture: bool,
    require_router_capture: bool,
    require_negative_reachability: bool,
    forbid_socks_proxy: bool,
}

/// Parse and validate a network profile manifest. `expected_id` is the
/// manifest filename stem; a mismatch with the embedded `id` fails closed.
pub fn parse_network_profile_toml(
    expected_id: &str,
    contents: &str,
) -> Result<NetworkProfile, String> {
    if contents.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(format!(
            "network profile manifest exceeds {MAX_MANIFEST_BYTES} bytes"
        ));
    }
    let raw: RawManifest = toml::from_str(contents)
        .map_err(|err| format!("network profile manifest is not valid: {err}"))?;
    if raw.schema_version != SUPPORTED_SCHEMA_VERSION {
        return Err(format!(
            "unsupported network profile schema_version {} (expected {SUPPORTED_SCHEMA_VERSION})",
            raw.schema_version
        ));
    }
    let id = NetworkProfileId::parse(&raw.id)?;
    if id.as_str() != expected_id {
        return Err(format!(
            "network profile id {:?} does not match its manifest filename stem {:?}",
            id.as_str(),
            expected_id
        ));
    }
    let evidence_tier = EvidenceTier::parse(&raw.evidence_tier)?;
    if raw.description.chars().count() > MAX_DESCRIPTION_CHARS {
        return Err(format!(
            "network profile description exceeds {MAX_DESCRIPTION_CHARS} characters"
        ));
    }
    if raw.description.chars().any(char::is_control) {
        return Err("network profile description contains control characters".to_owned());
    }

    let management = ManagementPolicy {
        attachment: ManagementAttachmentPolicy::parse(&raw.management.attachment)?,
        internet: raw.management.internet,
        peer_to_peer: raw.management.peer_to_peer,
        security_mode: ManagementSecurityMode::parse(&raw.management.security_mode)?,
    };

    let substrate = ScenarioSubstrate::parse(&raw.scenario.substrate)?;
    let address_family = AddressFamily::parse(&raw.scenario.address_family)?;
    let internet_mode = InternetMode::parse(&raw.scenario.internet_mode)?;

    let site_subnet_pool = raw
        .scenario
        .site_subnet_pool
        .as_deref()
        .map(IpCidr::parse)
        .transpose()?;
    let transit_subnet = raw
        .scenario
        .transit_subnet
        .as_deref()
        .map(IpCidr::parse)
        .transpose()?;

    let physical = match raw.scenario.physical {
        None => None,
        Some(raw_physical) => Some(validate_physical_policy(raw_physical)?),
    };

    let scenario = ScenarioPolicy {
        substrate,
        address_family,
        internet_mode,
        require_unique_site_subnets: raw.scenario.require_unique_site_subnets,
        site_subnet_pool,
        site_prefix_len: raw.scenario.site_prefix_len,
        transit_subnet,
        allow_cgnat_underlay_collision: raw.scenario.allow_cgnat_underlay_collision,
        requires_dedicated_oracle: raw.scenario.requires_dedicated_oracle,
        physical,
    };

    let evidence = EvidencePolicy {
        require_endpoint_capture: raw.evidence.require_endpoint_capture,
        require_router_capture: raw.evidence.require_router_capture,
        require_negative_reachability: raw.evidence.require_negative_reachability,
        forbid_socks_proxy: raw.evidence.forbid_socks_proxy,
    };

    let profile = NetworkProfile {
        schema_version: raw.schema_version,
        id,
        evidence_tier,
        description: raw.description,
        management,
        scenario,
        evidence,
    };
    validate_profile_coherence(&profile)?;
    Ok(profile)
}

fn validate_physical_policy(raw: RawPhysical) -> Result<PhysicalScenarioPolicy, String> {
    if raw.allowed_host_interfaces.is_empty() {
        return Err(
            "physical scenario policy must name at least one allowed host interface".to_owned(),
        );
    }
    if raw.allowed_host_interfaces.len() > MAX_PHYSICAL_INTERFACES {
        return Err(format!(
            "physical scenario policy lists more than {MAX_PHYSICAL_INTERFACES} interfaces"
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for interface in &raw.allowed_host_interfaces {
        if interface.len() < 2
            || interface.len() > 16
            || !interface
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        {
            return Err(format!(
                "physical interface name {interface:?} is invalid (expected 2-16 chars of [a-z0-9])"
            ));
        }
        if interface == FORBIDDEN_PHYSICAL_INTERFACE {
            return Err(format!(
                "physical interface {FORBIDDEN_PHYSICAL_INTERFACE:?} (the host's everyday LAN) is denied by policy and may never appear in a profile allowlist"
            ));
        }
        if !seen.insert(interface.clone()) {
            return Err(format!(
                "physical interface {interface:?} is listed more than once"
            ));
        }
    }
    Ok(PhysicalScenarioPolicy {
        allowed_host_interfaces: raw.allowed_host_interfaces,
    })
}

/// Cross-field coherence and address-plan validation (rulebook §15.2/§15.3).
fn validate_profile_coherence(profile: &NetworkProfile) -> Result<(), String> {
    let scenario = &profile.scenario;
    let mesh = mesh_overlay_cidr();

    if scenario.substrate == ScenarioSubstrate::None {
        if profile.evidence_tier != EvidenceTier::ManagementOnly {
            return Err(format!(
                "profile {} has no scenario substrate; its evidence tier must be management_only",
                profile.id
            ));
        }
        if scenario.internet_mode != InternetMode::None {
            return Err(format!(
                "profile {} has no scenario substrate; scenario internet_mode must be none",
                profile.id
            ));
        }
        if scenario.site_subnet_pool.is_some()
            || scenario.transit_subnet.is_some()
            || scenario.site_prefix_len.is_some()
        {
            return Err(format!(
                "profile {} has no scenario substrate; it must not declare scenario subnets",
                profile.id
            ));
        }
        if profile.evidence.require_endpoint_capture || profile.evidence.require_router_capture {
            return Err(format!(
                "profile {} has no scenario substrate; it cannot require scenario captures",
                profile.id
            ));
        }
        if scenario.allow_cgnat_underlay_collision {
            return Err(format!(
                "profile {} has no scenario substrate; the CGNAT collision flag is meaningless",
                profile.id
            ));
        }
    } else {
        if profile.evidence_tier == EvidenceTier::ManagementOnly {
            return Err(format!(
                "profile {} declares a scenario substrate but claims only the management_only tier",
                profile.id
            ));
        }
        if !profile.evidence.forbid_socks_proxy {
            return Err(format!(
                "profile {} produces network evidence; forbid_socks_proxy must be true (rulebook §9)",
                profile.id
            ));
        }
        if !profile.evidence.require_negative_reachability {
            return Err(format!(
                "profile {} produces network evidence; require_negative_reachability must be true",
                profile.id
            ));
        }
    }

    if scenario.allow_cgnat_underlay_collision && !scenario.requires_dedicated_oracle {
        return Err(format!(
            "profile {} allows the CGNAT underlay collision but does not require a dedicated oracle; the ordinary NAT oracle cannot be reused (rulebook §15.3)",
            profile.id
        ));
    }

    match (scenario.site_subnet_pool, scenario.site_prefix_len) {
        (Some(pool), Some(len)) => {
            if len <= pool.prefix() || len > 30 {
                return Err(format!(
                    "profile {} site_prefix_len {len} must be larger than the pool prefix {} and at most 30",
                    profile.id,
                    pool.prefix()
                ));
            }
        }
        (Some(_), None) => {
            return Err(format!(
                "profile {} declares site_subnet_pool without site_prefix_len",
                profile.id
            ));
        }
        (None, Some(_)) => {
            return Err(format!(
                "profile {} declares site_prefix_len without site_subnet_pool",
                profile.id
            ));
        }
        (None, None) => {}
    }

    let canonical_site_pool = IpCidr::parse(CANONICAL_SITE_POOL_CIDR).expect("constant valid");
    if let Some(pool) = &scenario.site_subnet_pool {
        if pool.overlaps(&mesh) {
            return Err(format!(
                "profile {} site pool {pool} overlaps the Rustynet mesh {MESH_OVERLAY_CIDR}; site subnets may never collide with the overlay",
                profile.id
            ));
        }
        if !pool.is_within(&canonical_site_pool) {
            return Err(format!(
                "profile {} site pool {pool} is outside the canonical scenario site range {CANONICAL_SITE_POOL_CIDR} (rulebook §15.3)",
                profile.id
            ));
        }
    }

    let canonical_transit = IpCidr::parse(CANONICAL_TRANSIT_CIDR).expect("constant valid");
    if let Some(transit) = &scenario.transit_subnet {
        let collides_with_mesh = transit.overlaps(&mesh);
        if collides_with_mesh && !scenario.allow_cgnat_underlay_collision {
            return Err(format!(
                "profile {} transit {transit} overlaps the Rustynet mesh {MESH_OVERLAY_CIDR}; only an explicit CGNAT collision profile may declare this (rulebook §15.3)",
                profile.id
            ));
        }
        if !collides_with_mesh && !transit.is_within(&canonical_transit) {
            return Err(format!(
                "profile {} transit {transit} is outside the canonical simulated-transit range {CANONICAL_TRANSIT_CIDR} (rulebook §15.3)",
                profile.id
            ));
        }
        if scenario.allow_cgnat_underlay_collision && !collides_with_mesh {
            return Err(format!(
                "profile {} sets the CGNAT collision flag but its transit {transit} does not overlap the mesh; drop the flag",
                profile.id
            ));
        }
        if let Some(pool) = &scenario.site_subnet_pool
            && pool.overlaps(transit)
        {
            return Err(format!(
                "profile {} site pool {pool} overlaps its transit {transit}",
                profile.id
            ));
        }
    } else if scenario.allow_cgnat_underlay_collision {
        return Err(format!(
            "profile {} sets the CGNAT collision flag without declaring the colliding transit subnet",
            profile.id
        ));
    }

    match scenario.substrate {
        ScenarioSubstrate::PhysicalInterface => {
            if scenario.physical.is_none() {
                return Err(format!(
                    "profile {} uses the physical_interface substrate but names no [scenario.physical] allowlist",
                    profile.id
                ));
            }
        }
        _ => {
            if scenario.physical.is_some() {
                return Err(format!(
                    "profile {} declares a physical interface allowlist but its substrate is {}",
                    profile.id,
                    scenario.substrate.as_str()
                ));
            }
        }
    }

    Ok(())
}

/// Load and validate every `*.toml` manifest directly inside `dir`
/// (non-recursive). Duplicate IDs and any invalid manifest fail the whole
/// load: a profile set is trusted only when every member validates.
pub fn load_network_profile_dir(
    dir: &Path,
) -> Result<BTreeMap<NetworkProfileId, NetworkProfile>, String> {
    let entries = fs::read_dir(dir).map_err(|err| {
        format!(
            "cannot read network profile directory {}: {err}",
            dir.display()
        )
    })?;
    let mut manifest_paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|err| format!("cannot enumerate {}: {err}", dir.display()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|err| format!("cannot stat {}: {err}", path.display()))?;
        if !file_type.is_file() {
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) == Some("toml") {
            manifest_paths.push(path);
        }
    }
    manifest_paths.sort();
    if manifest_paths.is_empty() {
        return Err(format!(
            "network profile directory {} contains no *.toml manifests",
            dir.display()
        ));
    }
    let mut profiles = BTreeMap::new();
    for path in manifest_paths {
        let stem = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .ok_or_else(|| format!("manifest {} has a non-UTF-8 filename", path.display()))?
            .to_owned();
        let metadata =
            fs::metadata(&path).map_err(|err| format!("cannot stat {}: {err}", path.display()))?;
        if metadata.len() > MAX_MANIFEST_BYTES {
            return Err(format!(
                "manifest {} exceeds {MAX_MANIFEST_BYTES} bytes",
                path.display()
            ));
        }
        let contents = fs::read_to_string(&path)
            .map_err(|err| format!("cannot read {}: {err}", path.display()))?;
        let profile = parse_network_profile_toml(&stem, &contents)
            .map_err(|err| format!("{}: {err}", path.display()))?;
        if profiles.contains_key(&profile.id) {
            return Err(format!(
                "duplicate network profile id {} in {}",
                profile.id,
                dir.display()
            ));
        }
        profiles.insert(profile.id.clone(), profile);
    }
    Ok(profiles)
}

/// Default on-repo manifest directory.
pub const DEFAULT_NETWORK_PROFILE_DIR: &str = "profiles/vm_lab/network";

/// The unique derived profile for runs launched without `--network-profile`.
/// Today's orchestrated runs exercise only the Shared management plane, so
/// the stage-set → profile mapping is unique and versioned (rulebook §15.4).
pub const DERIVED_DEFAULT_PROFILE_ID: &str = "mgmt_shared_smoke_v1";

/// Immutable per-run network-profile record, written to
/// `<report_dir>/orchestration/network_profile.json` at launch and verified
/// (digest recomputation against the on-repo manifests) before stages run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrchestrationNetworkProfileRecord {
    pub schema_version: u32,
    pub id: String,
    pub digest: String,
    pub evidence_tier: String,
    pub management_mode: String,
    pub scenario_substrate: String,
    pub address_family: String,
    pub internet_mode: String,
    /// True when the profile was derived from the stage set rather than
    /// passed explicitly with `--network-profile`.
    pub derived: bool,
    /// True when profile drift/compliance hard-blocks the run (always the
    /// case for an explicit `--network-profile`; derived management-only
    /// records observe and record without blocking until the fleet migration
    /// is approved and applied).
    pub enforced: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_evidence_path: Option<String>,
}

/// Resolve the run's network profile: the explicit `--network-profile` id, or
/// the unique derived management-plane default. Fails closed on an unknown or
/// invalid id and never falls back generically.
pub fn resolve_orchestration_network_profile(
    explicit: Option<&str>,
    profile_dir: &Path,
) -> Result<(NetworkProfile, bool), String> {
    let profiles = load_network_profile_dir(profile_dir)?;
    match explicit {
        Some(raw) => {
            let id = NetworkProfileId::parse(raw)?;
            let profile = profiles.get(&id).ok_or_else(|| {
                format!(
                    "network profile {raw:?} not found in {} (available: {})",
                    profile_dir.display(),
                    profiles
                        .keys()
                        .map(NetworkProfileId::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })?;
            Ok((profile.clone(), false))
        }
        None => {
            let id = NetworkProfileId::parse(DERIVED_DEFAULT_PROFILE_ID)?;
            let profile = profiles.get(&id).ok_or_else(|| {
                format!(
                    "derived default network profile {DERIVED_DEFAULT_PROFILE_ID:?} is missing from {}; the profile set is incomplete",
                    profile_dir.display()
                )
            })?;
            Ok((profile.clone(), true))
        }
    }
}

impl OrchestrationNetworkProfileRecord {
    pub fn from_profile(
        profile: &NetworkProfile,
        derived: bool,
        network_evidence_path: Option<String>,
    ) -> Self {
        Self {
            schema_version: 1,
            id: profile.id.as_str().to_owned(),
            digest: profile.canonical_digest(),
            evidence_tier: profile.evidence_tier.as_str().to_owned(),
            management_mode: format!(
                "{}:{}",
                profile.management.attachment.as_str(),
                profile.management.security_mode.as_str()
            ),
            scenario_substrate: profile.scenario.substrate.as_str().to_owned(),
            address_family: profile.scenario.address_family.as_str().to_owned(),
            internet_mode: profile.scenario.internet_mode.as_str().to_owned(),
            derived,
            enforced: !derived,
            network_evidence_path,
        }
    }

    /// Verify this record against the current on-repo manifests: the profile
    /// must still exist and its canonical digest must be unchanged. Any
    /// mismatch is profile drift and fails closed.
    pub fn verify_against_manifests(&self, profile_dir: &Path) -> Result<(), String> {
        let profiles = load_network_profile_dir(profile_dir)?;
        let id = NetworkProfileId::parse(&self.id)?;
        let profile = profiles.get(&id).ok_or_else(|| {
            format!(
                "network profile {} recorded for this run no longer exists in {}; profile drift fails the run",
                self.id,
                profile_dir.display()
            )
        })?;
        let current_digest = profile.canonical_digest();
        if current_digest != self.digest {
            return Err(format!(
                "network profile {} drifted after launch (recorded digest {}, current {current_digest}); the run fails closed",
                self.id, self.digest
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn netns_manifest() -> String {
        r#"
schema_version = 1
id = "crossnet_netns_v1"
evidence_tier = "netns"
description = "Deterministic Linux netns NAT/security regression substrate."

[management]
attachment = "shared"
internet = true
peer_to_peer = false
security_mode = "routine"

[scenario]
substrate = "netns"
address_family = "v4_only"
internet_mode = "simulated"
require_unique_site_subnets = true
site_subnet_pool = "172.20.0.0/16"
site_prefix_len = 24
transit_subnet = "198.18.0.0/15"

[evidence]
require_endpoint_capture = true
require_router_capture = true
require_negative_reachability = true
forbid_socks_proxy = true
"#
        .to_owned()
    }

    #[test]
    fn valid_netns_manifest_parses() {
        let profile = parse_network_profile_toml("crossnet_netns_v1", &netns_manifest()).unwrap();
        assert_eq!(profile.scenario.substrate, ScenarioSubstrate::Netns);
        assert_eq!(profile.evidence_tier, EvidenceTier::Netns);
        assert_eq!(
            profile.scenario.transit_subnet.unwrap().to_string(),
            "198.18.0.0/15"
        );
    }

    #[test]
    fn unknown_field_fails_closed() {
        let manifest =
            netns_manifest().replace("[management]", "surprise_field = true\n[management]");
        let err = parse_network_profile_toml("crossnet_netns_v1", &manifest).unwrap_err();
        assert!(err.contains("not valid"), "{err}");
    }

    #[test]
    fn unknown_enum_value_fails_closed() {
        let manifest =
            netns_manifest().replace("substrate = \"netns\"", "substrate = \"magic_bridge\"");
        let err = parse_network_profile_toml("crossnet_netns_v1", &manifest).unwrap_err();
        assert!(err.contains("unsupported scenario substrate"), "{err}");
    }

    #[test]
    fn id_filename_mismatch_fails_closed() {
        let err = parse_network_profile_toml("some_other_name", &netns_manifest()).unwrap_err();
        assert!(err.contains("does not match"), "{err}");
    }

    #[test]
    fn malformed_toml_fails_closed() {
        let err = parse_network_profile_toml("crossnet_netns_v1", "id = [broken").unwrap_err();
        assert!(err.contains("not valid"), "{err}");
    }

    #[test]
    fn wrong_schema_version_fails_closed() {
        let manifest = netns_manifest().replace("schema_version = 1", "schema_version = 2");
        let err = parse_network_profile_toml("crossnet_netns_v1", &manifest).unwrap_err();
        assert!(err.contains("schema_version"), "{err}");
    }

    #[test]
    fn mesh_transit_collision_rejected_without_explicit_flags() {
        let manifest = netns_manifest().replace(
            "transit_subnet = \"198.18.0.0/15\"",
            "transit_subnet = \"100.64.0.0/24\"",
        );
        let err = parse_network_profile_toml("crossnet_netns_v1", &manifest).unwrap_err();
        assert!(err.contains("overlaps the Rustynet mesh"), "{err}");
    }

    #[test]
    fn cgnat_collision_requires_dedicated_oracle() {
        let manifest = netns_manifest()
            .replace(
                "transit_subnet = \"198.18.0.0/15\"",
                "transit_subnet = \"100.64.0.0/24\"\nallow_cgnat_underlay_collision = true",
            )
            .replace("id = \"crossnet_netns_v1\"", "id = \"cgnat_collision_v1\"");
        let err = parse_network_profile_toml("cgnat_collision_v1", &manifest).unwrap_err();
        assert!(err.contains("dedicated oracle"), "{err}");
    }

    #[test]
    fn cgnat_collision_profile_with_oracle_parses() {
        let manifest = netns_manifest()
            .replace(
                "transit_subnet = \"198.18.0.0/15\"",
                "transit_subnet = \"100.64.0.0/24\"\nallow_cgnat_underlay_collision = true\nrequires_dedicated_oracle = true",
            )
            .replace("id = \"crossnet_netns_v1\"", "id = \"cgnat_collision_v1\"");
        let profile = parse_network_profile_toml("cgnat_collision_v1", &manifest).unwrap();
        assert!(profile.scenario.allow_cgnat_underlay_collision);
    }

    #[test]
    fn en0_rejected_in_physical_allowlist() {
        let manifest = netns_manifest()
            .replace(
                "substrate = \"netns\"",
                "substrate = \"physical_interface\"",
            )
            .replace(
                "[evidence]",
                "[scenario.physical]\nallowed_host_interfaces = [\"en0\"]\n\n[evidence]",
            )
            .replace(
                "evidence_tier = \"netns\"",
                "evidence_tier = \"physical_lab\"",
            );
        let err = parse_network_profile_toml("crossnet_netns_v1", &manifest).unwrap_err();
        assert!(err.contains("denied by policy"), "{err}");
    }

    #[test]
    fn physical_substrate_requires_allowlist() {
        let manifest = netns_manifest()
            .replace(
                "substrate = \"netns\"",
                "substrate = \"physical_interface\"",
            )
            .replace(
                "evidence_tier = \"netns\"",
                "evidence_tier = \"physical_lab\"",
            );
        let err = parse_network_profile_toml("crossnet_netns_v1", &manifest).unwrap_err();
        assert!(err.contains("names no [scenario.physical]"), "{err}");
    }

    #[test]
    fn evidence_profile_must_forbid_socks() {
        let manifest =
            netns_manifest().replace("forbid_socks_proxy = true", "forbid_socks_proxy = false");
        let err = parse_network_profile_toml("crossnet_netns_v1", &manifest).unwrap_err();
        assert!(err.contains("forbid_socks_proxy"), "{err}");
    }

    #[test]
    fn digest_is_stable_and_semantic() {
        let a = parse_network_profile_toml("crossnet_netns_v1", &netns_manifest()).unwrap();
        let b = parse_network_profile_toml(
            "crossnet_netns_v1",
            // Formatting-only change: extra blank lines and comment.
            &format!("# reviewed manifest\n\n{}", netns_manifest()),
        )
        .unwrap();
        assert_eq!(a.canonical_digest(), b.canonical_digest());
        let changed_manifest = netns_manifest().replace("internet = true", "internet = false");
        let c = parse_network_profile_toml("crossnet_netns_v1", &changed_manifest).unwrap();
        assert_ne!(a.canonical_digest(), c.canonical_digest());
        assert!(a.canonical_digest().starts_with("sha256:"));
    }

    #[test]
    fn cidr_overlap_math() {
        let mesh = IpCidr::parse("100.64.0.0/10").unwrap();
        let sim_wan = IpCidr::parse("100.64.0.0/24").unwrap();
        let transit = IpCidr::parse("198.18.0.0/15").unwrap();
        assert!(mesh.overlaps(&sim_wan));
        assert!(sim_wan.overlaps(&mesh));
        assert!(!transit.overlaps(&mesh));
        assert!(sim_wan.is_within(&mesh));
        assert!(!mesh.is_within(&sim_wan));
        assert!(mesh.contains_v4("100.99.1.2".parse().unwrap()));
        assert!(!mesh.contains_v4("192.168.64.4".parse().unwrap()));
        // Host bits set → reject.
        assert!(IpCidr::parse("100.64.0.1/10").is_err());
        assert!(IpCidr::parse("not-a-cidr").is_err());
        // IPv6 basics.
        let ula = IpCidr::parse("fd00::/8").unwrap();
        let ula_site = IpCidr::parse("fd21:69d4::/32").unwrap();
        assert!(ula.overlaps(&ula_site));
        assert!(!ula.overlaps(&mesh));
    }

    #[test]
    fn apple_backend_capability_matrix() {
        assert_eq!(
            backend_attachment_support(UtmBackend::Apple, AttachmentMode::HostOnly),
            CapabilitySupport::NotSupported
        );
        assert_eq!(
            backend_attachment_support(UtmBackend::Apple, AttachmentMode::Shared),
            CapabilitySupport::Supported
        );
        assert_eq!(
            backend_attachment_support(UtmBackend::Qemu, AttachmentMode::HostOnly),
            CapabilitySupport::Supported
        );
        assert_eq!(
            backend_multi_nic_support(UtmBackend::Apple),
            CapabilitySupport::Unproven
        );
    }

    #[test]
    fn backend_compatibility_fails_closed_for_apple_host_only() {
        let manifest =
            netns_manifest().replace("attachment = \"shared\"", "attachment = \"host_only\"");
        let profile = parse_network_profile_toml("crossnet_netns_v1", &manifest).unwrap();
        assert!(profile.backend_compatibility(UtmBackend::Apple).is_err());
        assert!(profile.backend_compatibility(UtmBackend::Qemu).is_ok());
    }

    #[test]
    fn attachment_mode_parse_fails_closed() {
        assert!(AttachmentMode::parse_utm("Host", UtmBackend::Apple).is_err());
        assert!(AttachmentMode::parse_utm("Mystery", UtmBackend::Qemu).is_err());
        assert_eq!(
            AttachmentMode::parse_utm("Bridged", UtmBackend::Apple).unwrap(),
            AttachmentMode::Bridged
        );
    }
}
