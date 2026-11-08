//! Topology-level cross-network substrate seam (CN-1 of
//! `CrossNetworkSubstrateIntegrationSpec_2026-06-21.md` §0.1, repositioned per
//! the §0.5 STATUS REFRESH design decision of 2026-08-27).
//!
//! The 2026-08-27 operator decision: the substrate seam lives at TOPOLOGY
//! level, not inside the cross-network suite. On a real 2-LAN fleet
//! `collect_pubkeys` records each node's raw discovered underlay endpoint and
//! `distribute_assignments` hands it out verbatim, so cross-LAN peers receive
//! endpoints on the other LAN's private prefix — unroutable. A substrate that
//! provisions an overlay must therefore run BEFORE `collect_pubkeys` and the
//! overlay addresses must be what lands in `ctx.endpoints`. SSH/management
//! traffic keeps using the management IPs throughout.
//!
//! Naming note: the pre-existing `CrossNetworkSubstrate` ENUM in
//! `cross_network.rs` stays as the CLI selector (`--cross-network-substrate`);
//! the provider abstraction here is deliberately named
//! [`CrossNetworkSubstrateProvider`] to avoid the collision.
//!
//! Leaf ops are argv-only (`ip`/`bridge` via sudo) — no shell string is ever
//! built from untrusted values (AGENTS.md §4); every argv element is validated
//! and single-quoted before it crosses the SSH boundary.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::process::Command;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The vxlan device name this substrate creates on each participating guest.
/// Deliberately `rustynet*`-prefixed so the final-cleanup residue assert
/// flags it loudly if teardown ever fails to remove it.
pub const VXLAN_LINK_NAME: &str = "rustynet-vx0";
/// VNI shared by the whole overlay mesh (head-end replicated full mesh).
pub const VXLAN_VNI: &str = "4242";
/// IANA VXLAN port, matching `vxlan_tier_b.sh`.
pub const VXLAN_DSTPORT: &str = "4789";
/// The source-port range the vxlan device is pinned to (`ip link add ...
/// srcport 4789 4790`, per the substrate-transit design): a FIXED range so
/// hash-based multipathing is deterministic and the daemon's transit rules
/// can pin `udp sport 4789 udp dport 4789` without ever seeing a straggler
/// outer packet from another source port.
pub const VXLAN_SRCPORT_LOW: &str = "4789";
pub const VXLAN_SRCPORT_HIGH: &str = "4790";
/// Canonical path of the guest `rustynet` CLI (mirrors the linux_install
/// adapter's `LINUX_RUSTYNET_PATH`; this module also compiles in the lib
/// tree where that binary-only module is not visible).
const GUEST_RUSTYNET_CLI: &str = "/usr/local/bin/rustynet";
/// Canonical path of the guest `rustynetd` (same mirroring rationale).
const GUEST_RUSTYNETD_BIN: &str = "/usr/local/bin/rustynetd";
/// The substrate-transit attestation file the daemon gates on (mirrors
/// `ops_vm_lab_substrate_transit::LAB_SUBSTRATE_TRANSIT_PATH`, binary-only).
pub const SUBSTRATE_TRANSIT_ATTESTATION_PATH: &str = "/etc/rustynet/lab/substrate-transit";
/// The nftables comment every substrate transit rule carries — the marker
/// the teardown residue assert and the security audit key on.
pub const SUBSTRATE_TRANSIT_RULE_COMMENT: &str = "rustynet_substrate_transit";
/// Canonical overlay pool (LiveLabVmConnectivityRulebook §15.3): addresses are
/// assigned out of per-group /24s inside 172.20.0.0/16, but configured with
/// the /16 mask so every group is on-link across the vxlan mesh.
pub const OVERLAY_PREFIX_LEN: u8 = 16;
/// The whole overlay pool, as the destination prefix a NAT'd site routes
/// through its router namespace.
pub const OVERLAY_POOL_CIDR: &str = "172.20.0.0/16";
/// Prefix length of the deterministic transit alias every overlay address
/// carries on the same device (see [`transit_alias_ip`]).
pub const TRANSIT_ALIAS_PREFIX_LEN: u8 = 16;
/// The transit-alias pool, as the destination prefix a NAT'd site routes
/// through its router namespace exactly like [`OVERLAY_POOL_CIDR`] — the
/// relay transport addresses must survive the same boundary the overlay
/// pool survives.
pub const TRANSIT_ALIAS_POOL_CIDR: &str = "198.18.0.0/16";
/// The substrate id [`VxlanSubstrateProvider`] records into
/// `SubstrateRecord::substrate_id`, which the orchestrator context persists
/// as `substrate_record` across a resume. Stages that must behave
/// differently on a provisioned overlay (e.g. the exit egress leak witness,
/// whose WireGuard control rides `rustynet-vx0` instead of the underlay)
/// compare against this constant instead of re-deriving the provider name.
pub const VXLAN_SUBSTRATE_ID: &str = "vxlan";

/// The router namespace a NAT-shaping profile builds on a participating guest
/// (CN-4). `rustynet*`-prefixed so the final-cleanup residue assert flags it.
///
/// The vxlan device MOVES into this namespace and keeps the node's overlay
/// address, so the address every peer was handed is still the address on the
/// wire — only the hop behind it changes. The guest's root namespace (where
/// `rustynetd` runs) sits on a private site LAN behind it, which is what makes
/// the translation real rather than cosmetic.
pub const VXLAN_ROUTER_NS: &str = "rustynet-vxr";
/// Root-namespace end of the site LAN veth pair.
pub const VXLAN_SITE_LAN_IF: &str = "rustynet-vxl";
/// Router-namespace end of the same pair (the site's default gateway).
pub const VXLAN_ROUTER_LAN_IF: &str = "rustynet-vxg";
/// The nftables table the router namespace's NAT rules live in.
pub const VXLAN_NAT_TABLE: &str = "rustynet_vxnat";
/// The WireGuard/relay UDP range `full_cone` DNATs inbound to the site host,
/// matching `scripts/vm_lab/apply_nat_profile.sh`'s default.
pub const NAT_WAN_UDP_PORTS: &str = "51820-51900";

/// Output of one leaf command. `success` is the command's own exit status;
/// a transport failure (ssh unreachable, spawn error) is the `Err` arm of
/// [`NetLeafRunner::run`] instead.
#[derive(Debug, Clone)]
pub struct LeafOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// HOW leaf ops run — the one place shell-out is allowed (`unsafe` netlink is
/// forbidden workspace-wide, so `ip`/`bridge` argv is the floor). Implementors:
/// [`LocalCommandRunner`] (same host), [`RemoteShellRunner`] (over the
/// existing hardened ssh helpers in `cross_network.rs`), and `MockLeafRunner`
/// (unit tests).
pub trait NetLeafRunner {
    /// Run one command given as argv. `Err` = the command could not be
    /// executed at all (transport/spawn failure); `Ok(LeafOutput)` reports
    /// the command's own exit status in `success`.
    fn run(&self, argv: &[&str]) -> Result<LeafOutput, String>;

    /// Run one argv inside a Linux network namespace, i.e.
    /// `ip netns exec <ns> <argv...>`.
    ///
    /// Provided (not required) so every backend gets namespace execution for
    /// free and no implementor can hand-roll a *different*, weaker prefix.
    /// The namespace name is validated against a strict allowlist BEFORE it
    /// is placed in argv position, so it can never smuggle an option (`-…`),
    /// a path component (`.`/`..`/`/`) or a shell metacharacter across the
    /// `RemoteShellRunner` quoting boundary.
    ///
    /// CN-2's `NetnsSubstrate` is the first consumer; it exists here because
    /// the spec (§0.1) puts it on the runner trait, and because putting it
    /// anywhere else would re-open the shell-construction hole.
    fn in_netns(&self, ns: &str, argv: &[&str]) -> Result<LeafOutput, String> {
        validate_netns_name(ns)?;
        validate_argv(argv)?;
        let mut full: Vec<&str> = vec!["ip", "netns", "exec", ns];
        full.extend_from_slice(argv);
        self.run(&full)
    }
}

/// Longest permitted network-namespace name. `ip netns` materialises each
/// namespace as a bind mount at `/var/run/netns/<name>`, so the name is a
/// filename and inherits the filesystem's component limit.
const MAX_NETNS_NAME_LEN: usize = 255;

/// Validate a network-namespace name: non-empty, length-bounded, ASCII
/// `[A-Za-z0-9_.-]` only, never a relative-path component, and never
/// option-looking. Deliberately an allowlist — a denylist here would be a
/// shell-injection hole one unusual character wide.
pub(crate) fn validate_netns_name(ns: &str) -> Result<(), String> {
    if ns.is_empty() {
        return Err("network namespace name must not be empty".to_owned());
    }
    if ns.len() > MAX_NETNS_NAME_LEN {
        return Err(format!(
            "network namespace name exceeds {MAX_NETNS_NAME_LEN} bytes: {ns:?}"
        ));
    }
    if ns == "." || ns == ".." {
        return Err(format!(
            "network namespace name must not be a path component: {ns:?}"
        ));
    }
    if ns.starts_with('-') {
        return Err(format!(
            "network namespace name must not look like an option: {ns:?}"
        ));
    }
    if !ns
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
    {
        return Err(format!(
            "network namespace name must contain only ASCII letters, digits, '.', '_' or '-': {ns:?}"
        ));
    }
    Ok(())
}

/// Reject argv elements that could break the quoting boundary. Every element
/// is later single-quoted, so the only characters that must never appear are
/// control characters (which would corrupt logs and can smuggle terminal
/// escapes) and empty elements (which vanish visually).
pub(crate) fn validate_argv(argv: &[&str]) -> Result<(), String> {
    if argv.is_empty() {
        return Err("leaf command argv must not be empty".to_owned());
    }
    for element in argv {
        if element.is_empty() {
            return Err("leaf command argv elements must not be empty".to_owned());
        }
        if element.chars().any(char::is_control) {
            return Err(format!(
                "leaf command argv element contains control characters: {element:?}"
            ));
        }
    }
    Ok(())
}

/// Single-quote one argv element for the remote `sh` boundary: `'` becomes
/// `'\''`, everything else is inert inside single quotes.
fn shell_quote(element: &str) -> String {
    format!("'{}'", element.replace('\'', "'\\''"))
}

/// Run leaf commands on the local host (netns-style substrates, future CN-2).
pub struct LocalCommandRunner;

impl NetLeafRunner for LocalCommandRunner {
    fn run(&self, argv: &[&str]) -> Result<LeafOutput, String> {
        validate_argv(argv)?;
        let output = Command::new(argv[0])
            .args(&argv[1..])
            .output()
            .map_err(|err| format!("failed to run local leaf command {:?}: {err}", argv[0]))?;
        Ok(LeafOutput {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

/// Run leaf commands on a lab guest over the existing hardened ssh transport
/// (`build_ssh_command` in `cross_network.rs`: BatchMode, strict host keys,
/// pinned known-hosts, identity-only). The remote command string is composed
/// ONLY from validated, individually quoted argv elements.
pub struct RemoteShellRunner {
    host: super::RemoteHost,
    log_path: PathBuf,
    label: String,
}

impl RemoteShellRunner {
    pub fn new(host: super::RemoteHost, log_path: PathBuf, label: String) -> Self {
        Self {
            host,
            log_path,
            label,
        }
    }
}

impl NetLeafRunner for RemoteShellRunner {
    fn run(&self, argv: &[&str]) -> Result<LeafOutput, String> {
        validate_argv(argv)?;
        let script = argv
            .iter()
            .map(|element| shell_quote(element))
            .collect::<Vec<_>>()
            .join(" ");
        let mut cmd = super::build_ssh_command(&self.host, &script);
        let output = cmd
            .output()
            .map_err(|err| format!("failed to run remote leaf command on {}: {err}", self.label))?;
        super::append_command_output(
            &self.log_path,
            &format!("{}: {script}", self.label),
            &output.stdout,
            &output.stderr,
        );
        Ok(LeafOutput {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

/// The provisioning inputs: every participating node's alias mapped to its
/// routable management IPv4 (the vxlan underlay).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubstrateTopology {
    pub nodes: BTreeMap<String, Ipv4Addr>,
}

/// The persisted half of a provisioned substrate: enough to fail closed on a
/// `--resume-from` mismatch and to tear the overlay down after a resume, but
/// never the live handle itself (runners and adapters are rebuilt per run).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubstrateRecord {
    /// Which substrate provisioned (e.g. "vxlan").
    pub substrate_id: String,
    /// Digest over the substrate id + every alias=underlay=overlay tuple, so
    /// a resumed run against a changed inventory fails closed instead of
    /// silently reusing stale overlay addressing.
    pub topology_digest: String,
    /// False when the substrate decided no overlay was needed (single
    /// network group) — teardown then has nothing to remove.
    pub provisioned: bool,
    /// Aliases that participate in the overlay (teardown fallback when the
    /// in-memory handle is gone after a resume).
    pub participants: Vec<String>,
}

/// What kind of kernel object a substrate created, so teardown removes it
/// with the right verb. A stringly-typed name alone could not distinguish
/// `ip link del` from `ip netns del`, and guessing wrong leaves residue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceKind {
    /// A network interface (`ip link del <name>`).
    Link,
    /// A network namespace (`ip netns del <name>`).
    Netns,
}

/// One kernel object this run created on a guest (exact teardown targets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedResource {
    pub alias: String,
    pub kind: ResourceKind,
    pub name: String,
}

impl CreatedResource {
    /// A created network interface on `alias`.
    pub fn link(alias: &str, name: &str) -> Self {
        Self {
            alias: alias.to_owned(),
            kind: ResourceKind::Link,
            name: name.to_owned(),
        }
    }

    /// A created network namespace on `alias`.
    pub fn netns(alias: &str, name: &str) -> Self {
        Self {
            alias: alias.to_owned(),
            kind: ResourceKind::Netns,
            name: name.to_owned(),
        }
    }
}

/// A live (or partially live) substrate. Holds per-node overlay + underlay
/// IPs keyed by alias. NOT serialized — only [`SubstrateRecord`] persists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubstrateHandle {
    pub record: SubstrateRecord,
    /// alias → overlay IPv4 (what `collect_pubkeys` must record into
    /// `ctx.endpoints` in place of the raw underlay IP).
    pub overlay_ips: BTreeMap<String, String>,
    /// alias → management/underlay IPv4 (SSH keeps using these).
    pub underlay_ips: BTreeMap<String, String>,
    /// Kernel objects actually created so far — appended as each creating
    /// command succeeds, so a partial setup still knows exactly what to
    /// remove. Ordered creation-first; teardown walks it in reverse.
    pub created_resources: Vec<CreatedResource>,
}

/// Which addressing plane an endpoint came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointPlane {
    /// The substrate-provisioned overlay address — what cross-LAN peers must
    /// be given as the dataplane endpoint.
    Overlay,
    /// The node's management/underlay address. Correct only when no overlay
    /// was needed (single network group); on a multi-LAN fleet an underlay
    /// endpoint is exactly the unroutable value the substrate exists to
    /// replace.
    Underlay,
}

/// Where a scenario node lives (spec §0.1 `SubstrateHandle::endpoint`). The
/// plane is carried alongside the address so a caller cannot mistake a
/// fallback underlay address for a provisioned overlay one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedEndpoint {
    pub alias: String,
    pub address: String,
    pub plane: EndpointPlane,
}

impl SubstrateHandle {
    /// Resolve one node's dataplane endpoint: the overlay address when the
    /// substrate provisioned one, otherwise the management/underlay address.
    /// `None` for an alias this substrate does not know — never a silently
    /// invented address.
    pub fn endpoint(&self, alias: &str) -> Option<ResolvedEndpoint> {
        if let Some(address) = self.overlay_ips.get(alias) {
            return Some(ResolvedEndpoint {
                alias: alias.to_owned(),
                address: address.clone(),
                plane: EndpointPlane::Overlay,
            });
        }
        self.underlay_ips
            .get(alias)
            .map(|address| ResolvedEndpoint {
                alias: alias.to_owned(),
                address: address.clone(),
                plane: EndpointPlane::Underlay,
            })
    }
}

/// Setup failure that keeps the partial state: the stage stores
/// `partial` on the context so the always-run teardown stage can remove
/// whatever was created before the failure (fail closed, never fail-and-leak).
#[derive(Debug)]
pub struct SubstrateSetupFailure {
    pub message: String,
    pub partial: SubstrateHandle,
}

/// The §D5.1 NAT-profile vocabulary as a closed set. Anything outside it is
/// rejected rather than passed through: a substrate asked about a profile it
/// has never heard of must not be able to answer "supported".
pub const KNOWN_NAT_PROFILES: &[&str] = &[
    "baseline_lan",
    "full_cone",
    "port_restricted_cone",
    "symmetric",
    "double_nat_cgnat",
];

/// A validated NAT-profile identifier (spec §0.1). Construction is the only
/// way in, so a `NatProfileId` in hand is always one of
/// [`KNOWN_NAT_PROFILES`].
///
/// This IS what `--cross-network-nat-profiles` parses into as of CN-4: the
/// owner-approved tightening (`OwnerDecisionDigest_2026-08-27.md` §16) removed
/// the flag's shape-only validation, so a name outside the vocabulary is a
/// parse-time error rather than a free string that reaches a substrate.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NatProfileId(String);

impl NatProfileId {
    /// Parse a profile name, fail-closed on anything unknown.
    pub fn parse(value: &str) -> Result<Self, String> {
        let trimmed = value.trim();
        match KNOWN_NAT_PROFILES.iter().find(|known| **known == trimmed) {
            Some(known) => Ok(Self((*known).to_owned())),
            None => Err(format!(
                "unknown NAT profile {trimmed:?}; expected one of {}",
                KNOWN_NAT_PROFILES.join("|")
            )),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for NatProfileId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether a substrate can realise a NAT profile (spec §0.1).
///
/// The point of the `UnsupportedByDesign` arm is that it carries a REASON, so
/// the caller records a typed, honest `Skipped` with that reason instead of
/// the shell era's bare `exit 2` (`netns_internet_sim.sh:189` for
/// `double_nat_cgnat`). It is not an error and must never be silently
/// swallowed into a pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Support {
    Supported,
    UnsupportedByDesign(String),
    /// The PROFILE is realisable but a requested [`NatModifiers`] toggle is
    /// not, on this substrate or in combination with this profile (CN-4).
    ///
    /// A separate arm rather than another `UnsupportedByDesign` string because
    /// the two mean different things to an operator: "this substrate cannot
    /// shape that NAT at all" versus "it can, but not with uPnP". Collapsing
    /// them would make evidence say the profile was out of reach when it was
    /// the modifier.
    UnsupportedModifier {
        modifier: String,
        reason: String,
    },
}

impl Support {
    pub fn is_supported(&self) -> bool {
        matches!(self, Self::Supported)
    }

    /// The documented reason a profile (or modifier combination) is out of
    /// reach, or `None` when it is supported.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Supported => None,
            Self::UnsupportedByDesign(reason) => Some(reason),
            Self::UnsupportedModifier { reason, .. } => Some(reason),
        }
    }
}

/// The `apply_nat_profile.sh` modifiers, carried as types rather than flags
/// (spec §0.2 point 5: "preserving `--enable-upnp`/`--enable-v6` as
/// `NatModifiers` — closing the `vxlan_tier_b.sh` gap where they are dropped
/// today").
///
/// - **uPnP available** starts an IGD/NAT-PMP responder on the site's LAN side
///   so the guest's port-mapping client (dataplane plan D2.3 / D14.a) can
///   obtain a real mapping. `cross_network_cold_enroll` needs it
///   (`+upnp_available` must enrol end to end; the same stage without it must
///   fail-with-correct-diagnosis).
/// - **IPv6 prefix** gives the site a natively routed v6 path alongside the v4
///   profile — no NAT66 — so `double_nat_anchor`'s "with `v6_native` the v4
///   path is bypassed" claim (§4.1.3, D14.b) is testable.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NatModifiers {
    upnp_available: bool,
    ipv6_prefix: Option<String>,
}

/// Longest lab IPv6 prefix length that still leaves host bits for the two site
/// addresses this crate assigns.
const MAX_LAB_V6_PREFIX_LEN: u8 = 120;

impl NatModifiers {
    /// No modifiers — the default, and what every existing caller means.
    pub fn none() -> Self {
        Self::default()
    }

    /// Request a uPnP/NAT-PMP responder on the site LAN.
    #[must_use]
    pub fn with_upnp(mut self) -> Self {
        self.upnp_available = true;
        self
    }

    /// Request a natively routed IPv6 prefix on the site LAN.
    ///
    /// Fail-closed validation: the prefix must parse as `<ipv6>/<len>`, must be
    /// a unique-local address (`fc00::/7`), and must leave host bits. The ULA
    /// requirement is deliberate — a lab that advertised a real global prefix
    /// on a guest's LAN would be announcing routes for address space it does
    /// not own, and there is no lab need for one.
    pub fn with_ipv6_prefix(mut self, prefix: &str) -> Result<Self, String> {
        let trimmed = prefix.trim();
        let (addr, len) = trimmed
            .split_once('/')
            .ok_or_else(|| format!("IPv6 modifier prefix must be <addr>/<len>: {trimmed:?}"))?;
        let parsed: Ipv6Addr = addr.parse().map_err(|_| {
            format!("IPv6 modifier prefix address is not an IPv6 literal: {addr:?}")
        })?;
        let len: u8 = len
            .parse()
            .map_err(|_| format!("IPv6 modifier prefix length is not a number: {len:?}"))?;
        if len == 0 || len > MAX_LAB_V6_PREFIX_LEN {
            return Err(format!(
                "IPv6 modifier prefix length must be 1..={MAX_LAB_V6_PREFIX_LEN}; got {len}"
            ));
        }
        if parsed.octets()[0] & 0xfe != 0xfc {
            return Err(format!(
                "IPv6 modifier prefix must be a unique-local address (fc00::/7); got {parsed}"
            ));
        }
        // The two site addresses are `<prefix>::1` and `<prefix>::2`, so the
        // supplied base must be the network address itself.
        if parsed.segments()[7] != 0 {
            return Err(format!(
                "IPv6 modifier prefix must be a network address ending in ::; got {parsed}"
            ));
        }
        self.ipv6_prefix = Some(format!("{parsed}/{len}"));
        Ok(self)
    }

    pub fn upnp_available(&self) -> bool {
        self.upnp_available
    }

    pub fn ipv6_prefix(&self) -> Option<&str> {
        self.ipv6_prefix.as_deref()
    }

    /// True when nothing is requested — the case every substrate can honour.
    pub fn is_empty(&self) -> bool {
        !self.upnp_available && self.ipv6_prefix.is_none()
    }

    /// The router-side and host-side site addresses for the requested prefix.
    /// `None` when no v6 prefix was requested.
    fn ipv6_site_addresses(&self) -> Option<(String, String, u8)> {
        let prefix = self.ipv6_prefix.as_deref()?;
        let (addr, len) = prefix.split_once('/')?;
        let base: Ipv6Addr = addr.parse().ok()?;
        let len: u8 = len.parse().ok()?;
        let mut gw = base.segments();
        gw[7] = 1;
        let mut host = base.segments();
        host[7] = 2;
        Some((
            Ipv6Addr::from(gw).to_string(),
            Ipv6Addr::from(host).to_string(),
            len,
        ))
    }

    /// One-line evidence rendering.
    pub fn describe(&self) -> String {
        if self.is_empty() {
            return "none".to_owned();
        }
        let mut parts = Vec::new();
        if self.upnp_available {
            parts.push("upnp_available".to_owned());
        }
        if let Some(prefix) = &self.ipv6_prefix {
            parts.push(format!("ipv6={prefix}"));
        }
        parts.join("+")
    }
}

/// Which NAT boundary inside a provisioned substrate a profile applies to
/// (spec §0.1 `apply_nat_profile(&self, site: SiteRef, …)`).
///
/// What a "site" names differs by substrate — a participating node alias for
/// vxlan, a simulated home network for netns — so the newtype carries only the
/// validated name and each provider resolves it. Validated on construction
/// against the same allowlist namespace names use, because it reaches argv
/// embedded in interface and namespace names.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SiteRef(String);

impl SiteRef {
    pub fn new(name: &str) -> Result<Self, String> {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err("site reference must not be empty".to_owned());
        }
        if trimmed.len() > 64 {
            return Err(format!("site reference exceeds 64 bytes: {trimmed:?}"));
        }
        if trimmed.starts_with('-') {
            return Err(format!(
                "site reference must not look like an option: {trimmed:?}"
            ));
        }
        if !trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
        {
            return Err(format!(
                "site reference must contain only ASCII letters, digits, '.', '_' or '-': \
                 {trimmed:?}"
            ));
        }
        Ok(Self(trimmed.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SiteRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why an `apply_nat_profile` call did not leave the site in the requested
/// shape. The two arms are deliberately distinct outcomes for the caller:
/// a refusal is a typed, honest `Skipped` with a reason; a failure is a stage
/// FAILURE over a site whose NAT state is now unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NatApplyError {
    /// This substrate does not realise the requested profile/modifier
    /// combination. Nothing was changed on the guest — the refusal is decided
    /// BEFORE the first leaf command, so there is no partial apply to unwind.
    Refused(Support),
    /// The apply itself failed (leaf command or transport). The site was reset
    /// to its un-NAT'd shape first, so what is left is knowable; teardown still
    /// sweeps whatever the reset could not remove.
    Failed(String),
}

impl NatApplyError {
    /// The human-readable half, for stage evidence.
    pub fn message(&self) -> String {
        match self {
            Self::Refused(support) => support
                .reason()
                .unwrap_or("refused without a reason")
                .to_owned(),
            Self::Failed(message) => message.clone(),
        }
    }
}

impl std::fmt::Display for NatApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(_) => write!(f, "refused: {}", self.message()),
            Self::Failed(_) => write!(f, "failed: {}", self.message()),
        }
    }
}

/// WHERE the overlay topology lives. Provisioned once by the
/// `cross_network_substrate_setup` stage (before `collect_pubkeys`), torn down
/// by the always-run `cross_network_substrate_teardown` stage.
pub trait CrossNetworkSubstrateProvider {
    fn id(&self) -> &'static str;

    /// Can this substrate realise `profile`? See [`Support`]: the
    /// `UnsupportedByDesign` arm is a typed, reasoned skip, not a failure.
    /// Required (no default) so a new substrate cannot inherit an
    /// over-permissive answer by omission.
    fn supports(&self, profile: &NatProfileId) -> Support;

    /// Can this substrate realise `profile` TOGETHER WITH `modifiers`?
    ///
    /// Required (no default) for the same reason [`Self::supports`] is: a
    /// default that answered "whatever the profile answers" would let a new
    /// substrate silently claim uPnP and IPv6 it never implements, and the
    /// modifier would then be dropped exactly as `vxlan_tier_b.sh` drops it
    /// today — the gap CN-4 exists to close.
    fn supports_with_modifiers(&self, profile: &NatProfileId, modifiers: &NatModifiers) -> Support;

    /// Reshape one already-provisioned site's NAT to `profile` + `modifiers`.
    ///
    /// Contract:
    /// - **Fail closed.** An unsupported combination is
    ///   [`NatApplyError::Refused`], decided before the first leaf command, so
    ///   a refusal never leaves a half-applied ruleset.
    /// - **Idempotent.** Every call resets the site to its un-NAT'd shape first
    ///   and rebuilds, so the resulting ruleset is a pure function of the
    ///   arguments (the property `apply_nat_profile.sh` documents as
    ///   "IDEMPOTENCE / DETERMINISM").
    /// - **argv-only.** Reshaping goes through the same [`NetLeafRunner`] as
    ///   provisioning; no shell string is built from any value here.
    /// - **Records what it creates.** Anything new lands in
    ///   `handle.created_resources` as it is created, so a failure part-way
    ///   still leaves teardown an exact target list.
    fn apply_nat_profile(
        &self,
        handle: &mut SubstrateHandle,
        site: &SiteRef,
        profile: &NatProfileId,
        modifiers: &NatModifiers,
        runners: &BTreeMap<String, &dyn NetLeafRunner>,
    ) -> Result<(), NatApplyError>;

    /// Stand up the overlay. On failure the partial handle inside the error
    /// still lists every link that was created. Boxed so the `Err` arm stays
    /// small (clippy `result_large_err`).
    fn setup(
        &self,
        topology: &SubstrateTopology,
        runners: &BTreeMap<String, &dyn NetLeafRunner>,
    ) -> Result<SubstrateHandle, Box<SubstrateSetupFailure>>;

    /// Remove everything the handle says was created. Must attempt every
    /// removal even when one fails, then report the joined failures.
    fn teardown(
        &self,
        handle: &SubstrateHandle,
        runners: &BTreeMap<String, &dyn NetLeafRunner>,
    ) -> Result<(), String>;
}

/// The overlay addressing plan: one /24 out of 172.20.0.0/16 per underlay
/// network group, one host address per node. `None` = fewer than two groups,
/// so no overlay is needed and the substrate is a recorded no-op.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayPlan {
    pub overlay_ips: BTreeMap<String, Ipv4Addr>,
    /// Aliases per network group, groups ordered by underlay prefix.
    pub groups: Vec<Vec<String>>,
}

/// Group nodes by their underlay /24 and assign overlay addresses:
/// group `g` (1-based) gets `172.20.<10*g>.0/24`, node `n` (0-based within
/// its group, aliases sorted) gets host octet `n + 2`.
pub fn plan_overlay(topology: &SubstrateTopology) -> Result<Option<OverlayPlan>, String> {
    let mut groups: BTreeMap<u32, Vec<String>> = BTreeMap::new();
    for (alias, ip) in &topology.nodes {
        groups
            .entry(u32::from(*ip) >> 8)
            .or_default()
            .push(alias.clone());
    }
    if groups.len() < 2 {
        return Ok(None);
    }
    if groups.len() > 24 {
        return Err(format!(
            "vxlan overlay supports at most 24 network groups; topology has {}",
            groups.len()
        ));
    }
    let mut overlay_ips = BTreeMap::new();
    let mut ordered_groups = Vec::new();
    for (group_index, (_, mut aliases)) in groups.into_iter().enumerate() {
        aliases.sort();
        let third_octet = 10 * (group_index as u8 + 1);
        if aliases.len() > 253 {
            return Err(format!(
                "vxlan overlay group {} has {} nodes; at most 253 fit in a /24",
                group_index + 1,
                aliases.len()
            ));
        }
        for (node_index, alias) in aliases.iter().enumerate() {
            let host_octet = node_index as u8 + 2;
            overlay_ips.insert(
                alias.clone(),
                Ipv4Addr::new(172, 20, third_octet, host_octet),
            );
        }
        ordered_groups.push(aliases);
    }
    Ok(Some(OverlayPlan {
        overlay_ips,
        groups: ordered_groups,
    }))
}

/// Deterministic locally-administered MAC for a node's vxlan device, derived
/// from its (unique) overlay IPv4: `02:52:<ip0>:<ip1>:<ip2>:<ip3>`.
///
/// An explicit MAC is load-bearing, not cosmetic. Lab guests are cloned from
/// one image and share `/etc/machine-id`; systemd's default
/// `MACAddressPolicy=persistent` then derives the SAME "persistent" MAC for a
/// same-named virtual device on every guest. The kernel's vxlan decap drops
/// any inner frame whose source MAC equals the receiving device's own address
/// (loop prevention), so with colliding MACs the overlay encaps and delivers
/// on the wire but every decap is silently discarded — RX stays 0 and no ARP
/// ever resolves. Verified live on two Debian 13 UTM guests (2026-08-27).
pub fn overlay_mac(overlay: Ipv4Addr) -> String {
    let o = overlay.octets();
    format!("02:52:{:02x}:{:02x}:{:02x}:{:02x}", o[0], o[1], o[2], o[3])
}

/// Deterministic transit alias for a node's overlay IPv4: `172.20.A.B` →
/// `198.18.A.B` (same last two octets, inside the IANA benchmarking range
/// `198.18.0.0/15` the netns substrate already simulates transit in).
///
/// The relay transport endpoint is resolved on the relay guest itself by
/// scanning `ip -o -4 addr show` for THE one 198.18.0.0/15 address
/// (provisioning.rs `relay_transport_endpoint`), so every participant gets
/// its alias as a SECONDARY address on the vxlan device — never the primary
/// overlay address, and never a separate interface. The alias is a pure
/// function of the overlay address, so it binds to the same
/// [`topology_digest`] without being named in it, and it disappears with
/// the device on teardown (`ip link del` drops every address).
pub fn transit_alias_ip(overlay: Ipv4Addr) -> Ipv4Addr {
    let [_, _, third, fourth] = overlay.octets();
    Ipv4Addr::new(198, 18, third, fourth)
}

/// Digest binding a substrate id to the exact alias/underlay/overlay tuples.
pub fn topology_digest(
    substrate_id: &str,
    topology: &SubstrateTopology,
    plan: Option<&OverlayPlan>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(substrate_id.as_bytes());
    hasher.update(b"\n");
    for (alias, underlay) in &topology.nodes {
        let overlay = plan
            .and_then(|p| p.overlay_ips.get(alias))
            .map(std::string::ToString::to_string)
            .unwrap_or_else(|| "none".to_owned());
        hasher.update(format!("{alias}={underlay}={overlay}\n").as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

/// The Tier-B VXLAN provider: the essential logic of
/// `scripts/vm_lab/vxlan_tier_b.sh`, ported onto [`NetLeafRunner`] with
/// argv-only leaf commands. Each participating guest gets one vxlan device
/// ([`VXLAN_LINK_NAME`], shared VNI, head-end-replication full mesh over the
/// routable management underlay) carrying its per-group overlay address, so
/// cross-LAN peers become mutually routable on 172.20.0.0/16.
pub struct VxlanSubstrateProvider;

impl VxlanSubstrateProvider {
    /// `setup` over EVERY participant when `aliases` is `None`, or over ONLY
    /// the given aliases (the post-reboot re-provision: never bounce the
    /// overlay on a node that did not reboot). The returned handle always
    /// describes the FULL topology (record participants, overlay/underlay
    /// maps), but `created_resources` lists only what THIS call created.
    fn setup_aliases(
        &self,
        topology: &SubstrateTopology,
        runners: &BTreeMap<String, &dyn NetLeafRunner>,
        aliases: Option<&[&str]>,
    ) -> Result<SubstrateHandle, Box<SubstrateSetupFailure>> {
        let underlay_ips: BTreeMap<String, String> = topology
            .nodes
            .iter()
            .map(|(alias, ip)| (alias.clone(), ip.to_string()))
            .collect();
        let fail = |message: String, partial: SubstrateHandle| {
            Box::new(SubstrateSetupFailure { message, partial })
        };
        let empty_handle = |digest: String| SubstrateHandle {
            record: SubstrateRecord {
                substrate_id: self.id().to_owned(),
                topology_digest: digest,
                provisioned: false,
                participants: Vec::new(),
            },
            overlay_ips: BTreeMap::new(),
            underlay_ips: underlay_ips.clone(),
            created_resources: Vec::new(),
        };
        let plan = match plan_overlay(topology) {
            Ok(plan) => plan,
            Err(err) => {
                let digest = topology_digest(self.id(), topology, None);
                return Err(fail(err, empty_handle(digest)));
            }
        };
        let digest = topology_digest(self.id(), topology, plan.as_ref());
        let Some(plan) = plan else {
            // Single network group: nothing to provision, recorded honestly.
            return Ok(empty_handle(digest));
        };
        let participants: Vec<String> = plan.overlay_ips.keys().cloned().collect();
        let mut handle = SubstrateHandle {
            record: SubstrateRecord {
                substrate_id: self.id().to_owned(),
                topology_digest: digest,
                provisioned: true,
                participants: participants.clone(),
            },
            overlay_ips: plan
                .overlay_ips
                .iter()
                .map(|(alias, ip)| (alias.clone(), ip.to_string()))
                .collect(),
            underlay_ips,
            created_resources: Vec::new(),
        };
        let every: Vec<&str> = participants.iter().map(String::as_str).collect();
        for alias in aliases.unwrap_or(every.as_slice()) {
            let runner = match Self::runner_for(runners, alias) {
                Ok(runner) => runner,
                Err(err) => return Err(fail(err, handle)),
            };
            if let Err(err) = self.provision_overlay_node(
                alias,
                &participants,
                &mut handle,
                &plan.overlay_ips,
                runner,
            ) {
                return Err(fail(err, handle));
            }
        }
        Ok(handle)
    }

    /// Provision ONE topology participant's overlay membership, in the
    /// documented per-node order: idempotent pre-delete, vxlan link, an fdb
    /// entry for every peer, the overlay address, up, and the transit
    /// attestation written LAST (a guest must never hold an attestation for
    /// a device that does not exist). Extracted verbatim from `setup` so
    /// the post-reboot re-provision can re-create ONLY the nodes that
    /// actually rebooted instead of bouncing the overlay under every live
    /// participant (review finding 3).
    fn provision_overlay_node(
        &self,
        alias: &str,
        participants: &[String],
        handle: &mut SubstrateHandle,
        plan_overlay_ips: &BTreeMap<String, Ipv4Addr>,
        runner: &dyn NetLeafRunner,
    ) -> Result<(), String> {
        let local = handle.underlay_ips[alias].clone();
        let overlay = handle.overlay_ips[alias].clone();
        let mac = overlay_mac(plan_overlay_ips[alias]);
        // Idempotent pre-delete: a leftover device from an aborted run is
        // expected, so a non-zero exit here is fine — but a transport
        // failure is not.
        runner
            .run(&["sudo", "-n", "ip", "link", "del", VXLAN_LINK_NAME])
            .map_err(|err| format!("{alias}: pre-delete: {err}"))?;
        Self::run_required(
            runner,
            alias,
            &[
                "sudo",
                "-n",
                "ip",
                "link",
                "add",
                VXLAN_LINK_NAME,
                "address",
                &mac,
                "type",
                "vxlan",
                "id",
                VXLAN_VNI,
                "local",
                &local,
                "dstport",
                VXLAN_DSTPORT,
                "srcport",
                VXLAN_SRCPORT_LOW,
                VXLAN_SRCPORT_HIGH,
                "nolearning",
            ],
        )?;
        handle
            .created_resources
            .push(CreatedResource::link(alias, VXLAN_LINK_NAME));
        for peer in participants {
            if peer.as_str() == alias {
                continue;
            }
            let peer_underlay = handle.underlay_ips[peer].clone();
            Self::run_required(
                runner,
                alias,
                &[
                    "sudo",
                    "-n",
                    "bridge",
                    "fdb",
                    "append",
                    "00:00:00:00:00:00",
                    "dev",
                    VXLAN_LINK_NAME,
                    "dst",
                    &peer_underlay,
                ],
            )?;
        }
        let overlay_cidr = format!("{overlay}/{OVERLAY_PREFIX_LEN}");
        Self::run_required(
            runner,
            alias,
            &[
                "sudo",
                "-n",
                "ip",
                "addr",
                "replace",
                &overlay_cidr,
                "dev",
                VXLAN_LINK_NAME,
            ],
        )?;
        // Secondary transit alias (see [`transit_alias_ip`]): `replace` is
        // idempotent, it never demotes the primary overlay address above, and
        // it dies with the device — no separate CreatedResource to sweep.
        let transit_alias_cidr = format!(
            "{}/{TRANSIT_ALIAS_PREFIX_LEN}",
            transit_alias_ip(plan_overlay_ips[alias])
        );
        Self::run_required(
            runner,
            alias,
            &[
                "sudo",
                "-n",
                "ip",
                "addr",
                "replace",
                &transit_alias_cidr,
                "dev",
                VXLAN_LINK_NAME,
            ],
        )?;
        Self::run_required(
            runner,
            alias,
            &["sudo", "-n", "ip", "link", "set", VXLAN_LINK_NAME, "up"],
        )?;
        // Substrate-transit attestation: the daemon gates its transit
        // ruleset on this file, so it is provisioned as part of the overlay
        // itself — a guest without it never enables transit.
        Self::write_transit_attestation(runner, alias, VXLAN_LINK_NAME, handle)?;
        Ok(())
    }
    fn runner_for<'a>(
        runners: &'a BTreeMap<String, &'a dyn NetLeafRunner>,
        alias: &str,
    ) -> Result<&'a dyn NetLeafRunner, String> {
        runners
            .get(alias)
            .copied()
            .ok_or_else(|| format!("no leaf runner for participating node '{alias}'"))
    }

    /// Run one required command: transport errors and non-zero exits both
    /// fail (closed), with the guest's stderr in the message.
    fn run_required(runner: &dyn NetLeafRunner, alias: &str, argv: &[&str]) -> Result<(), String> {
        let output = runner
            .run(argv)
            .map_err(|err| format!("{alias}: {argv:?}: {err}"))?;
        if output.success {
            Ok(())
        } else {
            Err(format!(
                "{alias}: {argv:?} failed: {}",
                output.stderr.trim()
            ))
        }
    }

    /// As [`Self::run_required`], but inside the router namespace.
    fn run_required_in_ns(
        runner: &dyn NetLeafRunner,
        alias: &str,
        ns: &str,
        argv: &[&str],
    ) -> Result<(), String> {
        let output = runner
            .in_netns(ns, argv)
            .map_err(|err| format!("{alias}: {ns}: {argv:?}: {err}"))?;
        if output.success {
            Ok(())
        } else {
            Err(format!(
                "{alias}: {ns}: {argv:?} failed: {}",
                output.stderr.trim()
            ))
        }
    }

    /// Teardown step (a): remove the substrate-transit attestation, retrying
    /// ONCE on any failure (a transient transport hiccup must not leave the
    /// boot rule armed). Both attempts failing is reported, and the caller
    /// carries on: the residue assertion at the end of the participant's
    /// teardown still reports the surviving file.
    fn remove_attestation_with_retry(
        runner: &dyn NetLeafRunner,
        alias: &str,
    ) -> Result<(), String> {
        let argv = remove_attestation_argv();
        match Self::run_required(runner, alias, &argv) {
            Ok(()) => Ok(()),
            Err(_first) => Self::run_required(runner, alias, &argv)
                .map_err(|err| format!("attestation removal failed twice: {err}")),
        }
    }

    /// Teardown step (b): restart `rustynetd` so its ExecStartPre rebuilds
    /// the persistent boot table from the CURRENT (now absent) attestation,
    /// dropping the transit allowance. `systemctl reset-failed` runs first,
    /// best-effort: a guest that crash-looped earlier in the run (u41-r2's
    /// `overlay device rustynet-vx0 does not exist` loop) arms systemd's
    /// start-rate limit, and an unguarded `restart` then fails with
    /// `Start request repeated too quickly` — turning the rebuild into a
    /// false residue report. A restart that still fails (both attempts) is
    /// residue (fail closed): the stale boot rule may still be armed. The
    /// other exception is a guest that has no `rustynetd` unit at all (setup
    /// failed before the install stage): there is no ExecStartPre to rebuild
    /// and no boot table this run could have created, and the nft residue
    /// assertion still verifies that.
    fn restart_daemon_for_boot_table(
        runner: &dyn NetLeafRunner,
        alias: &str,
    ) -> Result<(), String> {
        let restart_argv = restart_daemon_argv();
        let reset_argv = reset_failed_argv();
        let attempt = || -> Result<(), String> {
            // Best-effort: the reset cannot itself decide the outcome, the
            // restart below is the gate.
            let _ = runner.run(&reset_argv);
            match runner.run(&restart_argv) {
                Err(err) => Err(format!("{alias}: rustynetd restart: {err}")),
                Ok(output) if output.success => Ok(()),
                Ok(output) if daemon_unit_absent(&output.stderr) => Ok(()),
                Ok(output) => Err(format!(
                    "{alias}: rustynetd restart failed (boot table not rebuilt): {}",
                    output.stderr.trim()
                )),
            }
        };
        attempt().or_else(|_first| attempt())
    }

    /// Probe one guest's daemon for the `lab-substrate` feature. The probe
    /// is the daemon subcommand `lab-substrate-capability`; ANY failure
    /// (transport error, non-zero exit, a binary built before that
    /// subcommand existed) means "no capability" — fail closed, and the
    /// refusal message names the rebuild that fixes it.
    fn guest_substrate_capability(runner: &dyn NetLeafRunner) -> bool {
        match runner.run(&[
            "sudo",
            "-n",
            GUEST_RUSTYNETD_BIN,
            "lab-substrate-capability",
        ]) {
            Ok(output) if output.success => parse_substrate_capability(&output.stdout),
            _ => false,
        }
    }

    /// The overlay mesh peers of `alias`: every OTHER participant's underlay
    /// address, sorted — the exact list the fdb mesh above installed and the
    /// attestation must name.
    fn attestation_peers(handle: &SubstrateHandle, alias: &str) -> Vec<String> {
        let mut peers: Vec<String> = handle
            .underlay_ips
            .iter()
            .filter(|(peer, _)| peer.as_str() != alias)
            .map(|(_, underlay)| underlay.clone())
            .collect();
        peers.sort();
        peers
    }

    /// The underlay interface of `alias`: the device the guest's own route
    /// to the FIRST peer's underlay address leaves through. Derived on the
    /// guest (not from the orchestrator host) because the guest's routing
    /// table is what the transit rules are evaluated against.
    fn underlay_interface_for(
        runner: &dyn NetLeafRunner,
        alias: &str,
        peers: &[String],
    ) -> Result<String, String> {
        let first_peer = peers.first().ok_or_else(|| {
            format!("{alias}: no overlay peer to derive an underlay interface from")
        })?;
        let output = runner
            .run(&["sudo", "-n", "ip", "route", "get", first_peer])
            .map_err(|err| format!("{alias}: ip route get {first_peer}: {err}"))?;
        if !output.success {
            return Err(format!(
                "{alias}: ip route get {first_peer} failed: {}",
                output.stderr.trim()
            ));
        }
        parse_route_get_dev(&output.stdout).ok_or_else(|| {
            format!(
                "{alias}: ip route get {first_peer} did not name a device; \
                 cannot derive the substrate underlay interface"
            )
        })
    }

    /// Write the substrate-transit attestation on `alias` via the guest CLI
    /// subcommand. The leaf seam is argv-only (no file transfer), so the
    /// validated attestation is minted ON the guest by the same code the
    /// operator would run by hand — the daemon then re-validates the result.
    fn write_transit_attestation(
        runner: &dyn NetLeafRunner,
        alias: &str,
        overlay_interface: &str,
        handle: &SubstrateHandle,
    ) -> Result<(), String> {
        let peers = Self::attestation_peers(handle, alias);
        let underlay = Self::underlay_interface_for(runner, alias, &peers)?;
        let mut argv: Vec<&str> = vec![
            "sudo",
            "-n",
            GUEST_RUSTYNET_CLI,
            "ops",
            "vm-lab-write-substrate-transit",
            "--overlay-interface",
            overlay_interface,
            "--underlay-interface",
            &underlay,
        ];
        for peer in &peers {
            argv.push("--peer");
            argv.push(peer);
        }
        Self::run_required(runner, alias, &argv)
    }

    /// Best-effort removal: an object that was never there is the idempotent
    /// success case, but a TRANSPORT failure is not — we would be guessing
    /// about residue we cannot see.
    fn run_optional(runner: &dyn NetLeafRunner, alias: &str, argv: &[&str]) -> Result<(), String> {
        runner
            .run(argv)
            .map(|_| ())
            .map_err(|err| format!("{alias}: {argv:?}: {err}"))
    }

    /// Return the site to its flat, un-NAT'd shape: the vxlan device back in
    /// the guest's root namespace carrying the overlay address, no router
    /// namespace, no site LAN, no NAT table.
    ///
    /// This is both `baseline_lan`'s implementation AND the first half of every
    /// other profile's, which is what makes `apply_nat_profile` idempotent: the
    /// ruleset after a call depends only on that call's arguments, never on
    /// what the previous one left behind.
    fn reset_site_to_flat(
        runner: &dyn NetLeafRunner,
        alias: &str,
        overlay_cidr: &str,
        transit_alias_cidr: &str,
    ) -> Result<(), String> {
        // Move the device back out of the router namespace BEFORE deleting the
        // namespace: deleting a namespace destroys the virtual devices inside
        // it, and a destroyed vxlan device takes the node's overlay address
        // off the wire with no way to tell the peers.
        Self::run_optional(
            runner,
            alias,
            &[
                "sudo",
                "-n",
                "ip",
                "netns",
                "exec",
                VXLAN_ROUTER_NS,
                "ip",
                "link",
                "set",
                VXLAN_LINK_NAME,
                "netns",
                "1",
            ],
        )?;
        Self::run_optional(
            runner,
            alias,
            &["sudo", "-n", "ip", "netns", "del", VXLAN_ROUTER_NS],
        )?;
        // Deleting either end of a veth pair removes both.
        Self::run_optional(
            runner,
            alias,
            &["sudo", "-n", "ip", "link", "del", VXLAN_SITE_LAN_IF],
        )?;
        // Re-assert the flat addressing. `replace` is idempotent, and this is
        // what restores the overlay address after the device came back from the
        // namespace (moving a device between namespaces drops its addresses).
        Self::run_required(
            runner,
            alias,
            &[
                "sudo",
                "-n",
                "ip",
                "addr",
                "replace",
                overlay_cidr,
                "dev",
                VXLAN_LINK_NAME,
            ],
        )?;
        // The transit alias dropped with the same namespace move — re-assert
        // it too (same idempotent `replace`, same device).
        Self::run_required(
            runner,
            alias,
            &[
                "sudo",
                "-n",
                "ip",
                "addr",
                "replace",
                transit_alias_cidr,
                "dev",
                VXLAN_LINK_NAME,
            ],
        )?;
        Self::run_required(
            runner,
            alias,
            &["sudo", "-n", "ip", "link", "set", VXLAN_LINK_NAME, "up"],
        )
    }

    /// Build the router namespace and put the site behind it.
    fn build_router_site(
        runner: &dyn NetLeafRunner,
        handle: &mut SubstrateHandle,
        alias: &str,
        plan: &SiteAddressing,
        profile: &NatProfileId,
        modifiers: &NatModifiers,
    ) -> Result<(), String> {
        Self::run_required(
            runner,
            alias,
            &["sudo", "-n", "ip", "netns", "add", VXLAN_ROUTER_NS],
        )?;
        handle
            .created_resources
            .push(CreatedResource::netns(alias, VXLAN_ROUTER_NS));

        // The vxlan device becomes the router's WAN, keeping the overlay
        // address the peers were handed.
        Self::run_required(
            runner,
            alias,
            &[
                "sudo",
                "-n",
                "ip",
                "link",
                "set",
                VXLAN_LINK_NAME,
                "netns",
                VXLAN_ROUTER_NS,
            ],
        )?;
        Self::run_required_in_ns(
            runner,
            alias,
            VXLAN_ROUTER_NS,
            &[
                "sudo",
                "-n",
                "ip",
                "addr",
                "replace",
                &plan.overlay_cidr,
                "dev",
                VXLAN_LINK_NAME,
            ],
        )?;
        // The transit alias dropped when the device moved into the namespace;
        // re-assert it as the router's WAN-side alias (relay transport
        // endpoints resolve on this address, and the in-ns connected route
        // for 198.18.0.0/16 comes with it).
        Self::run_required_in_ns(
            runner,
            alias,
            VXLAN_ROUTER_NS,
            &[
                "sudo",
                "-n",
                "ip",
                "addr",
                "replace",
                &plan.transit_alias_cidr,
                "dev",
                VXLAN_LINK_NAME,
            ],
        )?;
        Self::run_required_in_ns(
            runner,
            alias,
            VXLAN_ROUTER_NS,
            &["sudo", "-n", "ip", "link", "set", VXLAN_LINK_NAME, "up"],
        )?;
        Self::run_required_in_ns(
            runner,
            alias,
            VXLAN_ROUTER_NS,
            &["sudo", "-n", "ip", "link", "set", "lo", "up"],
        )?;

        // The site LAN: root namespace (where rustynetd runs) behind the router.
        Self::run_required(
            runner,
            alias,
            &[
                "sudo",
                "-n",
                "ip",
                "link",
                "add",
                VXLAN_SITE_LAN_IF,
                "type",
                "veth",
                "peer",
                "name",
                VXLAN_ROUTER_LAN_IF,
            ],
        )?;
        handle
            .created_resources
            .push(CreatedResource::link(alias, VXLAN_SITE_LAN_IF));
        Self::run_required(
            runner,
            alias,
            &[
                "sudo",
                "-n",
                "ip",
                "link",
                "set",
                VXLAN_ROUTER_LAN_IF,
                "netns",
                VXLAN_ROUTER_NS,
            ],
        )?;
        Self::run_required(
            runner,
            alias,
            &[
                "sudo",
                "-n",
                "ip",
                "addr",
                "replace",
                &plan.host_cidr,
                "dev",
                VXLAN_SITE_LAN_IF,
            ],
        )?;
        Self::run_required(
            runner,
            alias,
            &["sudo", "-n", "ip", "link", "set", VXLAN_SITE_LAN_IF, "up"],
        )?;
        Self::run_required_in_ns(
            runner,
            alias,
            VXLAN_ROUTER_NS,
            &[
                "sudo",
                "-n",
                "ip",
                "addr",
                "replace",
                &plan.gateway_cidr,
                "dev",
                VXLAN_ROUTER_LAN_IF,
            ],
        )?;
        Self::run_required_in_ns(
            runner,
            alias,
            VXLAN_ROUTER_NS,
            &["sudo", "-n", "ip", "link", "set", VXLAN_ROUTER_LAN_IF, "up"],
        )?;
        // Only the overlay pool goes through the router — management/SSH keeps
        // using the guest's ordinary default route, which is what keeps the
        // control plane reachable while the dataplane is behind NAT.
        Self::run_required(
            runner,
            alias,
            &[
                "sudo",
                "-n",
                "ip",
                "route",
                "replace",
                OVERLAY_POOL_CIDR,
                "via",
                &plan.gateway_ip,
                "dev",
                VXLAN_SITE_LAN_IF,
            ],
        )?;
        // The transit-alias pool follows the exact same path: relay transport
        // endpoints (198.18.A.B) live on peer guests across the same boundary,
        // so without this route a NAT'd site would strand them.
        Self::run_required(
            runner,
            alias,
            &[
                "sudo",
                "-n",
                "ip",
                "route",
                "replace",
                TRANSIT_ALIAS_POOL_CIDR,
                "via",
                &plan.gateway_ip,
                "dev",
                VXLAN_SITE_LAN_IF,
            ],
        )?;
        Self::run_required_in_ns(
            runner,
            alias,
            VXLAN_ROUTER_NS,
            &["sudo", "-n", "sysctl", "-qw", "net.ipv4.ip_forward=1"],
        )?;

        Self::install_nat_rules(runner, alias, plan, profile)?;
        Self::apply_modifiers(runner, alias, plan, modifiers)
    }

    /// The per-profile nftables ruleset, matching
    /// `scripts/vm_lab/apply_nat_profile.sh`'s audited semantics.
    fn install_nat_rules(
        runner: &dyn NetLeafRunner,
        alias: &str,
        plan: &SiteAddressing,
        profile: &NatProfileId,
    ) -> Result<(), String> {
        Self::run_required_in_ns(
            runner,
            alias,
            VXLAN_ROUTER_NS,
            &["sudo", "-n", "nft", "add", "table", "ip", VXLAN_NAT_TABLE],
        )?;
        Self::run_required_in_ns(
            runner,
            alias,
            VXLAN_ROUTER_NS,
            &[
                "sudo",
                "-n",
                "nft",
                "add",
                "chain",
                "ip",
                VXLAN_NAT_TABLE,
                "post",
                "{ type nat hook postrouting priority srcnat; policy accept; }",
            ],
        )?;
        fn masquerade(extra: Option<&str>) -> Vec<&str> {
            let mut argv = vec![
                "sudo",
                "-n",
                "nft",
                "add",
                "rule",
                "ip",
                VXLAN_NAT_TABLE,
                "post",
                "oifname",
                VXLAN_LINK_NAME,
                "masquerade",
            ];
            if let Some(extra) = extra {
                argv.push(extra);
            }
            argv
        }
        match profile.as_str() {
            // Plain conntrack masquerade: endpoint-INDEPENDENT mapping (the
            // source port is preserved when free) with endpoint-DEPENDENT
            // filtering. The common consumer-router shape.
            "port_restricted_cone" => {
                Self::run_required_in_ns(runner, alias, VXLAN_ROUTER_NS, &masquerade(None))?;
            }
            // Forced port randomisation: every flow gets a fresh source port,
            // so the mapping is endpoint-DEPENDENT and the peer cannot reuse a
            // learned endpoint — the shape that forces relay fallback.
            "symmetric" => {
                Self::run_required_in_ns(
                    runner,
                    alias,
                    VXLAN_ROUTER_NS,
                    &masquerade(Some("random")),
                )?;
            }
            // Masquerade plus a DMZ-style DNAT of the WireGuard UDP range to
            // the site host: endpoint-independent mapping AND filtering, so an
            // unsolicited inbound lands.
            "full_cone" => {
                Self::run_required_in_ns(runner, alias, VXLAN_ROUTER_NS, &masquerade(None))?;
                Self::run_required_in_ns(
                    runner,
                    alias,
                    VXLAN_ROUTER_NS,
                    &[
                        "sudo",
                        "-n",
                        "nft",
                        "add",
                        "chain",
                        "ip",
                        VXLAN_NAT_TABLE,
                        "pre",
                        "{ type nat hook prerouting priority dstnat; policy accept; }",
                    ],
                )?;
                Self::run_required_in_ns(
                    runner,
                    alias,
                    VXLAN_ROUTER_NS,
                    &[
                        "sudo",
                        "-n",
                        "nft",
                        "add",
                        "rule",
                        "ip",
                        VXLAN_NAT_TABLE,
                        "pre",
                        "iifname",
                        VXLAN_LINK_NAME,
                        "udp",
                        "dport",
                        NAT_WAN_UDP_PORTS,
                        "dnat",
                        "to",
                        &plan.host_ip,
                    ],
                )?;
            }
            // Unreachable: `apply_nat_profile` gates on `supports_with_modifiers`
            // before the first leaf command. Kept as a hard error rather than a
            // silent no-op so a profile added to the vocabulary later cannot
            // quietly build a NAT-less site that then "passes" its gate.
            other => {
                return Err(format!(
                    "vxlan substrate has no rule set for NAT profile {other:?}; \
                     supports_with_modifiers() must gate this before apply"
                ));
            }
        }
        Ok(())
    }

    /// uPnP and native IPv6, the two `apply_nat_profile.sh` modifiers.
    fn apply_modifiers(
        runner: &dyn NetLeafRunner,
        alias: &str,
        plan: &SiteAddressing,
        modifiers: &NatModifiers,
    ) -> Result<(), String> {
        if modifiers.upnp_available() {
            // miniupnpd is configured entirely through argv here rather than
            // through the config file `apply_nat_profile.sh` writes: an
            // argv-only leaf runner cannot redirect a heredoc into a file, and
            // reintroducing a shell to do it would re-open exactly the
            // construction hole AGENTS.md §4 forbids. `-i` names the external
            // (overlay-facing) interface, `-a` the LAN address it listens on,
            // `-N` enables NAT-PMP alongside IGD.
            Self::run_required_in_ns(
                runner,
                alias,
                VXLAN_ROUTER_NS,
                &[
                    "sudo",
                    "-n",
                    "miniupnpd",
                    "-i",
                    VXLAN_LINK_NAME,
                    "-a",
                    &plan.gateway_ip,
                    "-N",
                ],
            )?;
        }
        if let Some((gateway_v6, host_v6, prefix_len)) = modifiers.ipv6_site_addresses() {
            let gateway_cidr = format!("{gateway_v6}/{prefix_len}");
            let host_cidr = format!("{host_v6}/{prefix_len}");
            Self::run_required_in_ns(
                runner,
                alias,
                VXLAN_ROUTER_NS,
                &[
                    "sudo",
                    "-n",
                    "sysctl",
                    "-qw",
                    "net.ipv6.conf.all.forwarding=1",
                ],
            )?;
            Self::run_required_in_ns(
                runner,
                alias,
                VXLAN_ROUTER_NS,
                &[
                    "sudo",
                    "-n",
                    "ip",
                    "-6",
                    "addr",
                    "replace",
                    &gateway_cidr,
                    "dev",
                    VXLAN_ROUTER_LAN_IF,
                ],
            )?;
            Self::run_required(
                runner,
                alias,
                &[
                    "sudo",
                    "-n",
                    "ip",
                    "-6",
                    "addr",
                    "replace",
                    &host_cidr,
                    "dev",
                    VXLAN_SITE_LAN_IF,
                ],
            )?;
            // Native v6 routing, no NAT66 — the point of the modifier is that
            // the v4 NAT can be bypassed entirely.
            Self::run_required(
                runner,
                alias,
                &[
                    "sudo",
                    "-n",
                    "ip",
                    "-6",
                    "route",
                    "replace",
                    "default",
                    "via",
                    &gateway_v6,
                    "dev",
                    VXLAN_SITE_LAN_IF,
                ],
            )?;
        }
        Ok(())
    }
}

/// The private site addressing a NAT'd vxlan node sits on, derived
/// deterministically from its overlay address so two nodes never collide.
///
/// Overlay `172.20.G.H` yields site LAN `10.G.H.0/24` with the router at `.1`
/// and the guest's root namespace at `.2`. The overlay third/fourth octets are
/// unique per node by construction (`plan_overlay`), so the derived /24 is too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteAddressing {
    pub overlay_cidr: String,
    pub transit_alias_cidr: String,
    pub gateway_ip: String,
    pub gateway_cidr: String,
    pub host_ip: String,
    pub host_cidr: String,
}

impl SiteAddressing {
    /// Derive the site plan for one node's overlay address.
    pub fn for_overlay(overlay: Ipv4Addr) -> Self {
        let o = overlay.octets();
        let gateway_ip = format!("10.{}.{}.1", o[2], o[3]);
        let host_ip = format!("10.{}.{}.2", o[2], o[3]);
        Self {
            overlay_cidr: format!("{overlay}/{OVERLAY_PREFIX_LEN}"),
            transit_alias_cidr: format!("{}/{TRANSIT_ALIAS_PREFIX_LEN}", transit_alias_ip(overlay)),
            gateway_cidr: format!("{gateway_ip}/24"),
            gateway_ip,
            host_cidr: format!("{host_ip}/24"),
            host_ip,
        }
    }
}

impl CrossNetworkSubstrateProvider for VxlanSubstrateProvider {
    fn id(&self) -> &'static str {
        VXLAN_SUBSTRATE_ID
    }

    /// WIDENED IN CN-4, in the same change that wired
    /// [`CrossNetworkSubstrateProvider::apply_nat_profile`] — deliberately not
    /// before it. Widening first would have turned "the profile silently did
    /// nothing" into a false pass; leaving it narrow afterwards would have
    /// turned a capability that exists into a false skip.
    ///
    /// - `baseline_lan` — SUPPORTED. Exactly what `setup` builds: a flat,
    ///   routable overlay with no translation anywhere.
    /// - `port_restricted_cone` / `full_cone` / `symmetric` — SUPPORTED.
    ///   `apply_nat_profile` moves the node's vxlan device into a router
    ///   namespace on its own guest and puts the root namespace (where
    ///   `rustynetd` runs) behind it on a private site LAN, so the three
    ///   `apply_nat_profile.sh` rulesets translate real traffic. The node's
    ///   overlay address is unchanged — it is now the router's WAN address, so
    ///   the endpoint every peer was handed is still the address on the wire.
    /// - `double_nat_cgnat` — REFUSED. A vxlan site has exactly ONE router
    ///   namespace; the carrier hop chained behind it is the netns substrate's
    ///   `rnsim-cgn-*` chain (CN-4), which owns the CGNAT topology.
    fn supports(&self, profile: &NatProfileId) -> Support {
        match profile.as_str() {
            "baseline_lan" | "port_restricted_cone" | "full_cone" | "symmetric" => {
                Support::Supported
            }
            "double_nat_cgnat" => Support::UnsupportedByDesign(
                "double_nat_cgnat needs a two-router carrier chain; a vxlan site has exactly one \
                 router namespace — the CGNAT chain lives in the netns substrate"
                    .to_owned(),
            ),
            other => Support::UnsupportedByDesign(format!(
                "{other} is outside the vxlan substrate's NAT vocabulary"
            )),
        }
    }

    /// Modifiers need somewhere to live, and on this substrate that place is
    /// the router namespace — so a modifier requested alongside `baseline_lan`
    /// (which builds no router) is refused rather than silently dropped, which
    /// is the `vxlan_tier_b.sh` behaviour CN-4 exists to end.
    fn supports_with_modifiers(&self, profile: &NatProfileId, modifiers: &NatModifiers) -> Support {
        let base = self.supports(profile);
        if !base.is_supported() || modifiers.is_empty() {
            return base;
        }
        if profile.as_str() == "baseline_lan" {
            return Support::UnsupportedModifier {
                modifier: modifiers.describe(),
                reason: "baseline_lan builds no router namespace on the guest, so there is no \
                         NAT boundary for a uPnP responder or a routed IPv6 prefix to sit on; \
                         request a NAT-shaping profile or no modifiers"
                    .to_owned(),
            };
        }
        Support::Supported
    }

    fn apply_nat_profile(
        &self,
        handle: &mut SubstrateHandle,
        site: &SiteRef,
        profile: &NatProfileId,
        modifiers: &NatModifiers,
        runners: &BTreeMap<String, &dyn NetLeafRunner>,
    ) -> Result<(), NatApplyError> {
        // Refuse BEFORE the first leaf command: a refusal must never leave a
        // half-applied ruleset behind.
        let support = self.supports_with_modifiers(profile, modifiers);
        if !support.is_supported() {
            return Err(NatApplyError::Refused(support));
        }
        if !handle.record.provisioned {
            return Err(NatApplyError::Failed(format!(
                "cannot apply NAT profile '{profile}' to site '{site}': the vxlan substrate \
                 provisioned no overlay for this topology"
            )));
        }
        // A vxlan site IS a participating node alias.
        let alias = site.as_str();
        let overlay = handle.overlay_ips.get(alias).cloned().ok_or_else(|| {
            NatApplyError::Failed(format!(
                "no vxlan overlay address for site '{site}'; it is not a participating node"
            ))
        })?;
        let overlay: Ipv4Addr = overlay.parse().map_err(|_| {
            NatApplyError::Failed(format!(
                "vxlan overlay address for site '{site}' is not an IPv4 literal: {overlay:?}"
            ))
        })?;
        let plan = SiteAddressing::for_overlay(overlay);
        let runner =
            Self::runner_for(runners, alias).map_err(|err| NatApplyError::Failed(err.clone()))?;

        // Reset first, always: the ruleset after this call must be a pure
        // function of its arguments, not of whatever the last one left.
        Self::reset_site_to_flat(runner, alias, &plan.overlay_cidr, &plan.transit_alias_cidr)
            .map_err(NatApplyError::Failed)?;
        // Anything the previous profile created is gone now, so the recorded
        // resource list must stop naming it.
        handle
            .created_resources
            .retain(|resource| !is_vxlan_nat_resource(resource, alias));
        if profile.as_str() == "baseline_lan" {
            // The site is back to flat L2: the daemon-facing overlay is the
            // vxlan link in the ROOT namespace again, so the attestation
            // must say so (a stale vxl attestation would leave transit
            // enabled against an interface the daemon no longer owns).
            if let Err(err) =
                Self::write_transit_attestation(runner, alias, VXLAN_LINK_NAME, handle)
            {
                return Err(NatApplyError::Failed(err));
            }
            return Ok(());
        }
        if let Err(err) = Self::build_router_site(runner, handle, alias, &plan, profile, modifiers)
        {
            return Err(NatApplyError::Failed(err));
        }
        // With a router site applied the vxlan device LIVES in the router
        // namespace and the daemon-facing overlay is the site LAN veth —
        // rewrite the attestation so the daemon's transit rules follow it.
        if let Err(err) = Self::write_transit_attestation(runner, alias, VXLAN_SITE_LAN_IF, handle)
        {
            return Err(NatApplyError::Failed(err));
        }
        Ok(())
    }

    fn setup(
        &self,
        topology: &SubstrateTopology,
        runners: &BTreeMap<String, &dyn NetLeafRunner>,
    ) -> Result<SubstrateHandle, Box<SubstrateSetupFailure>> {
        self.setup_aliases(topology, runners, None)
    }

    fn teardown(
        &self,
        handle: &SubstrateHandle,
        runners: &BTreeMap<String, &dyn NetLeafRunner>,
    ) -> Result<(), String> {
        if !handle.record.provisioned {
            return Ok(());
        }
        // Exact created resources when we have them (covers partial setup and
        // whatever `apply_nat_profile` built); otherwise every recorded
        // participant with the well-known names (covers teardown after a resume
        // where the live handle was rebuilt from the persisted record and can
        // no longer say whether a NAT profile was applied).
        let targets: Vec<CreatedResource> = if handle.created_resources.is_empty() {
            handle
                .record
                .participants
                .iter()
                .flat_map(|alias| {
                    [
                        // Namespace first: it owns the vxlan device while a NAT
                        // profile is applied, and the link removal below is the
                        // idempotent no-op when no profile ever was.
                        CreatedResource::netns(alias, VXLAN_ROUTER_NS),
                        CreatedResource::link(alias, VXLAN_SITE_LAN_IF),
                        CreatedResource::link(alias, VXLAN_LINK_NAME),
                    ]
                })
                .collect()
        } else {
            // Reverse creation order so a namespace is removed before the
            // interfaces recorded before it.
            let mut ordered = handle.created_resources.clone();
            ordered.reverse();
            ordered
        };
        // Per-participant order is SECURITY-MANDATORY (daemon review
        // finding 16): the daemon's persistent boot table carries a narrow
        // transit allowance for as long as the attestation exists at
        // ExecStartPre time. Deleting the vxlan link first would leave that
        // allowance armed with no overlay behind it (a local unprivileged
        // process could bind the freed port 4789 and use it). So, for each
        // participant, strictly:
        //   (a) remove the attestation (one retry; a failure is recorded as
        //       residue but does NOT stop the teardown — a half-up overlay is
        //       worse than a reported residue),
        //   (b) clear the crash-loop start-rate limit (reset-failed) and
        //       restart rustynetd so ExecStartPre rebuilds the boot table
        //       WITHOUT the transit rule (failure = residue, fail closed),
        //   (c) ONLY THEN delete the vxlan/veth links and the router netns,
        //   (d) revert the egress pin, then the residue assertion (nft
        //       ruleset carries no transit rule, attestation absent).
        // The order is pinned by `teardown_runs_attestation_removal_and_daemon_restart_before_link_deletion`.
        let mut aliases: Vec<&str> = Vec::new();
        for target in &targets {
            if !aliases.contains(&target.alias.as_str()) {
                aliases.push(target.alias.as_str());
            }
        }
        let mut errors = Vec::new();
        for alias in aliases {
            let runner = match Self::runner_for(runners, alias) {
                Ok(runner) => runner,
                Err(err) => {
                    errors.push(err);
                    continue;
                }
            };
            // (a) The substrate-transit attestation the setup wrote. The
            // removal subcommand is idempotent (missing = success), so this is
            // safe to re-run after a resume or a partial teardown.
            if let Err(err) = Self::remove_attestation_with_retry(runner, alias) {
                errors.push(err);
            }
            // (b) Rebuild the boot table without the transit rule.
            if let Err(err) = Self::restart_daemon_for_boot_table(runner, alias) {
                errors.push(err);
            }
            // (c) Links and namespaces, in the order computed above.
            for target in targets.iter().filter(|target| target.alias == alias) {
                // A namespace and an interface need different removal verbs;
                // guessing wrong reports a pass over real residue.
                let argv: Vec<&str> = match target.kind {
                    ResourceKind::Link => vec!["sudo", "-n", "ip", "link", "del", &target.name],
                    ResourceKind::Netns => vec!["sudo", "-n", "ip", "netns", "del", &target.name],
                };
                match runner.run(&argv) {
                    Err(err) => errors.push(format!("{}: {err}", target.alias)),
                    Ok(output) if !output.success => {
                        // Already-gone is the idempotent success case; anything
                        // else is potential residue and must fail the stage.
                        if !already_removed(&output.stderr) {
                            errors.push(format!(
                                "{}: delete {} failed: {}",
                                target.alias,
                                target.name,
                                output.stderr.trim()
                            ));
                        }
                    }
                    Ok(_) => {}
                }
            }
            // (d) Second residue class, on the same guest: the daemon env-file
            // egress pin the overlay caused `ops install-systemd` to write.
            // Runs after the links are gone, over exactly the aliases the
            // removal loop touched — a guest that never had an overlay link
            // never had a route through one either, so it cannot carry a pin
            // from this run, and widening the set to every recorded
            // participant would newly fail teardown on a guest with no
            // runner. Both well-known link names are offered every time;
            // deletion is keyed on an exact value match, so a name that was
            // never pinned costs nothing.
            if let Err(err) =
                revert_egress_pins(runner, alias, &[VXLAN_LINK_NAME, VXLAN_SITE_LAN_IF])
            {
                errors.push(err);
            }
            // Residue assertion: the daemon's transit nft rules and the
            // attestation file itself, asserted AFTER the removal and restart
            // above. Both probes fail closed — a probe that cannot run is
            // reported as possible residue, never a silent pass.
            match runner.run(&["sudo", "-n", "nft", "list", "ruleset"]) {
                Err(err) => errors.push(format!("{alias}: nft residue probe: {err}")),
                Ok(output) if !output.success => errors.push(format!(
                    "{alias}: nft list ruleset failed: {}",
                    output.stderr.trim()
                )),
                Ok(output) => {
                    // `test ! -e <path>` exits 0 only when the file is gone;
                    // non-zero here IS the residue signal.
                    let attestation_present = runner
                        .run(&attestation_absent_argv())
                        .map(|output| !output.success)
                        .unwrap_or(true);
                    for err in substrate_residue_errors(&output.stdout, attestation_present) {
                        errors.push(format!("{alias}: {err}"));
                    }
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "vxlan substrate teardown left possible residue: {}",
                errors.join("; ")
            ))
        }
    }
}

/// Does a `rustynetd lab-substrate-capability` stdout declare the feature?
/// Only the exact first non-empty line `lab-substrate=yes` counts.
fn parse_substrate_capability(stdout: &str) -> bool {
    stdout.lines().map(str::trim).find(|line| !line.is_empty()) == Some("lab-substrate=yes")
}

/// The capability refusal, verbatim from the substrate-transit design: it
/// must name the flag that fixes the build, because the operator who sees it
/// has just hit a host/guest feature skew the message alone can resolve.
fn substrate_capability_refusal(alias: &str) -> String {
    format!(
        "guest rustynetd on {alias} was built without the lab-substrate feature, \
         which --cross-network-substrate vxlan needs; rebuild the lab binaries with \
         --features rustynetd/lab-substrate (the host-cross build does this by default)"
    )
}

/// Parse the `dev <name>` out of `ip route get <address>` stdout. `None`
/// when no device is named — callers fail closed instead of guessing.
/// (Mirrors `ops_vm_lab_substrate_transit::parse_route_get_dev`; that
/// module is binary-only, this tree also builds in the lib.)
fn parse_route_get_dev(stdout: &str) -> Option<String> {
    let line = stdout.lines().next()?;
    let mut fields = line.split_whitespace();
    while let Some(field) = fields.next() {
        if field == "dev" {
            return fields.next().map(str::to_owned);
        }
    }
    None
}

/// Fail-closed substrate residue check: given a full `nft list ruleset`
/// dump and whether the attestation file still exists, name EVERY residue
/// class still present (empty = clean). Keyed on the exact rule comment the
/// daemon stamps, so ordinary lab nft rules never trip it.
fn substrate_residue_errors(ruleset: &str, attestation_present: bool) -> Vec<String> {
    let mut errors = Vec::new();
    if ruleset.contains(SUBSTRATE_TRANSIT_RULE_COMMENT) {
        errors.push(format!(
            "nft ruleset still carries '{SUBSTRATE_TRANSIT_RULE_COMMENT}' rules"
        ));
    }
    if attestation_present {
        errors.push(format!(
            "attestation file {SUBSTRATE_TRANSIT_ATTESTATION_PATH} is still present"
        ));
    }
    errors
}

/// The argv that removes the attestation on a guest (idempotent subcommand).
fn remove_attestation_argv() -> Vec<&'static str> {
    vec![
        "sudo",
        "-n",
        GUEST_RUSTYNET_CLI,
        "ops",
        "vm-lab-remove-substrate-transit",
    ]
}

/// The argv that restarts the guest daemon so ExecStartPre rebuilds the boot
/// table. Plain `restart` (not `try-restart`): a stopped daemon's boot table
/// persists, and only a start re-runs ExecStartPre.
fn restart_daemon_argv() -> Vec<&'static str> {
    vec!["sudo", "-n", "systemctl", "restart", "rustynetd"]
}

/// The argv that clears systemd's per-unit start-rate limit
/// (`Start request repeated too quickly`) so a guest that crash-looped
/// earlier in the run can still have its daemon restarted for the boot-table
/// rebuild. Run before every restart attempt, best-effort.
fn reset_failed_argv() -> Vec<&'static str> {
    vec!["sudo", "-n", "systemctl", "reset-failed", "rustynetd"]
}

/// `systemctl restart` on a unit the guest never had.
fn daemon_unit_absent(stderr: &str) -> bool {
    let lowered = stderr.to_ascii_lowercase();
    lowered.contains("unit rustynetd.service not found")
        || lowered.contains("unit rustynetd.service could not be found")
}

/// The argv that asserts attestation ABSENCE: `test ! -e <path>` exits 0
/// when the file is gone (the only clean answer) and non-zero when residue
/// remains.
fn attestation_absent_argv() -> Vec<&'static str> {
    vec![
        "sudo",
        "-n",
        "test",
        "!",
        "-e",
        SUBSTRATE_TRANSIT_ATTESTATION_PATH,
    ]
}

/// Mirrors `ops_install_systemd::ENV_DST`; the substrate is Linux-only (setup
/// fails closed on any non-Linux participant), so no per-OS variant is needed.
const DAEMON_ENV_FILE: &str = "/etc/default/rustynetd";

/// Build the `sed` program that deletes an egress pin naming `link`.
///
/// Every `ip link` name this substrate creates is plain ASCII, so an
/// allowlisted character set keeps the value inert as a regular expression.
/// A name outside that set is refused rather than interpolated — a metacharacter
/// here would silently widen the deletion to lines it was never meant to touch.
fn egress_pin_delete_program(link: &str) -> Result<String, String> {
    if link.is_empty()
        || !link
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
    {
        return Err(format!(
            "refusing to build an egress-pin deletion for interface name {link:?}: \
             only ASCII letters, digits, '_' and '-' are permitted"
        ));
    }
    Ok(format!("/^RUSTYNET_EGRESS_INTERFACE={link}$/d"))
}

/// Remove any `RUSTYNET_EGRESS_INTERFACE` pin in the guest's daemon env file
/// that names an interface THIS substrate created.
///
/// Why teardown owns this at all: nothing here writes that file directly, but
/// the overlay is what causes it to be written wrong. While the overlay is up,
/// the route to the selected exit endpoint leaves through the vxlan link, so
/// `ops install-systemd` derives that link as the egress interface and pins it
/// (`ops_install_systemd.rs`, `resolve_egress_interface` →
/// `RUSTYNET_EGRESS_INTERFACE`). Deleting the link without deleting the pin
/// leaves a value naming a device that no longer exists, and the next ordinary
/// install on that guest fails `egress interface does not exist`. That is
/// residue in the §10.7 sense — the run that created it must revert it.
///
/// Keyed on an exact value match, so a pin naming a real NIC is never touched,
/// and reverting a name that was never pinned is a no-op. The provenance marker
/// line is deliberately left alone: with no value line to describe it, the
/// installer never consults it, and the next install rewrites the file whole.
fn revert_egress_pins(
    runner: &dyn NetLeafRunner,
    alias: &str,
    links: &[&str],
) -> Result<(), String> {
    let mut programs = Vec::with_capacity(links.len());
    for link in links {
        programs.push(egress_pin_delete_program(link)?);
    }
    let mut argv: Vec<&str> = vec!["sudo", "-n", "sed", "-i"];
    for program in &programs {
        argv.push("-e");
        argv.push(program.as_str());
    }
    argv.push(DAEMON_ENV_FILE);
    match runner.run(&argv) {
        Err(err) => Err(format!("{alias}: {err}")),
        // A guest with no env file was never installed, so it carries no pin.
        Ok(output) if !output.success && !already_removed(&output.stderr) => Err(format!(
            "{alias}: reverting the egress interface pin in {DAEMON_ENV_FILE} failed: {}",
            output.stderr.trim()
        )),
        Ok(_) => Ok(()),
    }
}

/// Resources `apply_nat_profile` creates on a vxlan site, so a re-apply can
/// drop them from the recorded list once the reset has removed them.
fn is_vxlan_nat_resource(resource: &CreatedResource, alias: &str) -> bool {
    resource.alias == alias
        && matches!(
            (resource.kind, resource.name.as_str()),
            (ResourceKind::Netns, VXLAN_ROUTER_NS) | (ResourceKind::Link, VXLAN_SITE_LAN_IF)
        )
}

/// `ip link del` / `ip netns del` on something already gone is the idempotent
/// success case; anything else is potential residue and must fail the stage.
fn already_removed(stderr: &str) -> bool {
    let lowered = stderr.to_ascii_lowercase();
    lowered.contains("cannot find device")
        || lowered.contains("no such file or directory")
        || lowered.contains("cannot remove namespace file")
}

/// Whether a selected substrate owns the TOPOLOGY-LEVEL seam — i.e. whether
/// it provisions cross-LAN overlay addresses before `collect_pubkeys` records
/// endpoints.
///
/// Not every substrate does, and saying so out loud is the point. The netns
/// simulator's endpoints are namespaces inside ONE guest, not lab node
/// aliases (spec §3: "Tier A = the deterministic NAT-matrix gate ... it does
/// NOT run the SSH e2e validators"), and it is built and torn down per NAT
/// profile by the classification gate, so provisioning it here would hold a
/// topology across thirty unrelated stages that the gate then rebuilds anyway.
pub enum TopologySeam {
    /// Provisions an overlay; the setup stage drives it.
    Provisions(Box<dyn CrossNetworkSubstrateProvider>),
    /// Provisions no overlay at topology level, with the reason.
    NoOverlay(&'static str),
}

/// Dispatch the selected substrate to its topology-level behaviour.
pub fn topology_level_seam(substrate: CrossNetworkSubstrate) -> TopologySeam {
    match substrate {
        CrossNetworkSubstrate::Vxlan => TopologySeam::Provisions(Box::new(VxlanSubstrateProvider)),
        CrossNetworkSubstrate::Netns => TopologySeam::NoOverlay(
            "the netns simulator's endpoints are namespaces inside one guest, not lab node \
             aliases; it provisions no cross-LAN overlay and is built per NAT profile by the \
             cross_network_nat_classification gate",
        ),
        CrossNetworkSubstrate::Slirp => TopologySeam::NoOverlay(
            "the slirp substrate's NAT belongs to the hypervisor (UTM 'Shared Network', applied \
             before boot), so it provisions no overlay and creates nothing on the guest; see \
             `slirp::SlirpSubstrateProvider`, which verifies the guests really are behind it",
        ),
    }
}

/// The provider that owns a PERSISTED record, keyed by the id in the record
/// itself rather than by what this run selected.
///
/// Teardown must remove what was actually created: dispatching on the current
/// `--cross-network-substrate` would, after a flag change across a resume,
/// hand a vxlan overlay to a netns teardown and silently leave the residue.
/// (`check_record_against_request` rejects that mismatch first; this is the
/// second lock on the same door.)
///
/// Only `vxlan` appears here because only `vxlan` ever records
/// `provisioned: true` at topology level. The netns simulator is built and
/// swept per profile by the classification gate, and the slirp substrate
/// creates nothing at all (it records `provisioned: false`), so
/// `teardown_with` returns before it would ever ask for either — and if one
/// day one of them did record a provisioned topology, the `None` arm's hard
/// failure is the correct answer rather than a guessed teardown.
pub fn provider_for_record(substrate_id: &str) -> Option<Box<dyn CrossNetworkSubstrateProvider>> {
    match substrate_id {
        "vxlan" => Some(Box::new(VxlanSubstrateProvider)),
        _ => None,
    }
}

// ───────────────────────────── lifecycle stages ─────────────────────────────

use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

use super::{CrossNetworkOptions, CrossNetworkSubstrate};

/// Resolve every assigned node's alias → management IPv4 from its adapter's
/// SSH parameters. Fail closed on a node with no SSH params or a
/// non-IPv4-literal host: an overlay planned over an incomplete topology
/// would hand out endpoints some peers cannot use.
fn substrate_topology_from_ctx(ctx: &OrchestrationContext) -> Result<SubstrateTopology, String> {
    let mut nodes = BTreeMap::new();
    for assignment in &ctx.assignments {
        let alias = assignment.alias.as_str();
        let adapter = ctx
            .adapters
            .get(alias)
            .ok_or_else(|| format!("substrate topology: no adapter for '{alias}'"))?;
        let params = adapter
            .ssh_connection_params()
            .ok_or_else(|| format!("substrate topology: '{alias}' has no SSH connection params"))?;
        let host = super::strip_ssh_host(params.host.as_str());
        let ip: Ipv4Addr = host.parse().map_err(|_| {
            format!("substrate topology: '{alias}' management host {host:?} is not an IPv4 literal")
        })?;
        nodes.insert(alias.to_owned(), ip);
    }
    Ok(SubstrateTopology { nodes })
}

/// Build one hardened remote leaf runner per assigned node.
fn build_remote_runners(
    ctx: &OrchestrationContext,
    stage_name: &str,
) -> Result<Vec<(String, RemoteShellRunner)>, String> {
    let log_path = ctx
        .report_dir
        .join(stage_name)
        .join("substrate_leaf_commands.log");
    let mut runners = Vec::new();
    for assignment in &ctx.assignments {
        let alias = assignment.alias.clone();
        let host = super::remote_host_for_alias(ctx, &alias)?;
        runners.push((
            alias.clone(),
            RemoteShellRunner::new(host, log_path.clone(), alias),
        ));
    }
    Ok(runners)
}

fn runner_refs(runners: &[(String, RemoteShellRunner)]) -> BTreeMap<String, &dyn NetLeafRunner> {
    runners
        .iter()
        .map(|(alias, runner)| (alias.clone(), runner as &dyn NetLeafRunner))
        .collect()
}

/// The requested-vs-persisted provenance check shared by setup and teardown.
/// Any disagreement between what this run requests and what the persisted
/// record says a previous (resumed) run provisioned is a hard failure.
fn check_record_against_request(
    record: Option<&SubstrateRecord>,
    requested_id: Option<&str>,
    current_digest: Option<&str>,
) -> Result<(), String> {
    let Some(record) = record else {
        return Ok(());
    };
    match requested_id {
        None => Err(format!(
            "substrate provenance mismatch: the persisted context records substrate '{}' \
             but this run requests none; refusing to continue over unknown overlay state \
             (re-run setup or tear the lab down)",
            record.substrate_id
        )),
        Some(requested_id) if requested_id != record.substrate_id => Err(format!(
            "substrate provenance mismatch: persisted substrate '{}' but this run requests \
             '{requested_id}'",
            record.substrate_id
        )),
        Some(_) => match current_digest {
            Some(digest) if digest != record.topology_digest => Err(format!(
                "substrate topology mismatch on resume: persisted digest {} but this run's \
                 topology digests to {digest}; the inventory changed under the overlay — \
                 refusing to reuse stale overlay addressing",
                record.topology_digest
            )),
            _ => Ok(()),
        },
    }
}

/// Re-provision the persisted substrate after a stage rebooted guests.
///
/// The vxlan overlay is volatile guest state: a reboot loses the
/// `rustynet-vx0` device (and its fdb/addresses) while the persistent
/// attestation at `SUBSTRATE_TRANSIT_ATTESTATION_PATH` survives, so the
/// daemon's ExecStartPre rebuilds a boot table whose transit rules reference
/// an overlay device that no longer exists and the daemon refuses to start
/// (u41-r2: `overlay device rustynet-vx0 does not exist`).
///
/// ONLY the nodes that actually rebooted are re-created (review finding 3):
/// running setup over every participant would pre-delete and re-add
/// `rustynet-vx0` under LIVE daemons on the other nodes — a transient
/// overlay outage and a new ifindex this run does not need. The re-created
/// nodes' resources are MERGED into the live handle instead of replacing
/// it, so teardown still removes everything the run ever created. fdb
/// entries still name every peer, so a rebooted node rejoins the full mesh.
///
/// Fail-closed: a persisted substrate this code has no provider for, a
/// topology whose digest disagrees with the persisted record, or a
/// rebooted alias that is not a topology participant is a hard error —
/// never a silent skip. A run with no provisioned substrate (netns, slirp,
/// or a recorded no-op) is untouched. On a failed re-provision the partial
/// handle is recorded (merged with the previous state) so teardown still
/// removes whatever was created.
pub(crate) fn reprovision_substrate_after_guest_reboot(
    ctx: &mut OrchestrationContext,
    topology: &SubstrateTopology,
    runners: &BTreeMap<String, &dyn NetLeafRunner>,
    rebooted: &[&str],
) -> Result<(), String> {
    let Some(record) = ctx.substrate_record.clone() else {
        return Ok(());
    };
    if !record.provisioned {
        return Ok(());
    }
    // The re-provision path is inherently the vxlan provider's
    // (`setup_aliases` is its operation); a record naming any other
    // substrate stays fail-closed instead of widening the provider trait
    // for one caller.
    let provider = VxlanSubstrateProvider;
    if provider.id() != record.substrate_id {
        return Err(format!(
            "no re-provision provider for persisted substrate '{}'; refusing to continue \
             over unknown overlay state",
            record.substrate_id
        ));
    }
    let plan = plan_overlay(topology)?;
    let digest = topology_digest(provider.id(), topology, plan.as_ref());
    check_record_against_request(Some(&record), Some(provider.id()), Some(&digest))?;
    for alias in rebooted {
        if !topology.nodes.contains_key(*alias) {
            return Err(format!(
                "rebooted node '{alias}' is not a participant of the substrate topology; \
                 refusing to re-provision an inventory it does not belong to"
            ));
        }
    }
    match provider.setup_aliases(topology, runners, Some(rebooted)) {
        Ok(handle) => {
            let mut handle = handle;
            if let Some(previous) = ctx.substrate.as_ref() {
                handle.created_resources =
                    merge_created_resources(&previous.created_resources, handle.created_resources);
            }
            ctx.substrate_record = Some(handle.record.clone());
            ctx.substrate = Some(handle);
            Ok(())
        }
        Err(failure) => {
            let mut partial = failure.partial;
            if let Some(previous) = ctx.substrate.as_ref() {
                partial.created_resources =
                    merge_created_resources(&previous.created_resources, partial.created_resources);
            }
            ctx.substrate_record = Some(partial.record.clone());
            ctx.substrate = Some(partial);
            Err(format!(
                "{} substrate re-provision after a guest reboot failed (partial state \
                 recorded for teardown): {}",
                provider.id(),
                failure.message
            ))
        }
    }
}

/// Union of the resources a previous provision created and the ones a
/// re-provision just created, deduplicated: a rebooted node's vxlan link is
/// pre-deleted and re-added under the SAME name, so both lists name it.
fn merge_created_resources(
    previous: &[CreatedResource],
    fresh: Vec<CreatedResource>,
) -> Vec<CreatedResource> {
    let mut merged = previous.to_vec();
    for resource in fresh {
        if !merged.contains(&resource) {
            merged.push(resource);
        }
    }
    merged
}

/// How long the post-reboot daemon recovery may take: 30 polls, 2 s apart
/// (29 sleeps ≈ 58 s plus probe time — the review's "up to ~60 s" budget).
pub(crate) const DAEMON_ACTIVE_POLL_ATTEMPTS: usize = 30;
pub(crate) const DAEMON_ACTIVE_POLL_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(2);

/// A wireguard handshake older than this (or none at all) fails the
/// post-reboot verification: the rebooted pair must have re-keyed after the
/// reboot for the mesh to count as re-converged.
pub(crate) const WG_HANDSHAKE_MAX_AGE_SECS: u64 = 600;

/// Boundedly poll `systemctl is-active rustynetd` until it prints exactly
/// `active` TWICE in a row (one clean read could race the unit flapping
/// between auto-restart attempts). Sleeps between polls via `sleep`, never
/// before the first probe. Fails with the last observed state after
/// `attempts` probes.
fn poll_daemon_active(
    runner: &dyn NetLeafRunner,
    alias: &str,
    attempts: usize,
    sleep: &dyn Fn(std::time::Duration),
) -> Result<(), String> {
    let argv = ["sudo", "-n", "systemctl", "is-active", "rustynetd"];
    let mut consecutive_active = 0usize;
    let mut last_state = "no probe ran".to_owned();
    for attempt in 0..attempts {
        if attempt > 0 {
            sleep(DAEMON_ACTIVE_POLL_INTERVAL);
        }
        match runner.run(&argv) {
            Err(err) => {
                consecutive_active = 0;
                last_state = format!("probe error: {err}");
            }
            Ok(output) => {
                let state = output.stdout.trim();
                if output.success && state == "active" {
                    consecutive_active += 1;
                    if consecutive_active >= 2 {
                        return Ok(());
                    }
                } else {
                    consecutive_active = 0;
                }
                last_state = state.to_owned();
            }
        }
    }
    Err(format!(
        "{alias}: rustynetd did not reach a stable active state after the restart \
         ({attempts} polls, last observed state {last_state:?})"
    ))
}

/// Recover ONE rebooted guest's daemon (review finding 1): clear the
/// systemd start-limit latch (`reset-failed`, best-effort — the teardown
/// restart path's same ordering), `restart` rustynetd so ExecStartPre
/// rebuilds the boot table / transit rules against the re-provisioned
/// overlay, then bounded-poll for a stable active state. A restart that
/// still fails, or a unit that vanished, is a hard error — the stage must
/// not pass a guest it cannot verify.
fn recover_daemon_after_reboot(
    runner: &dyn NetLeafRunner,
    alias: &str,
    sleep: &dyn Fn(std::time::Duration),
) -> Result<(), String> {
    let _ = runner.run(&reset_failed_argv());
    let output = runner
        .run(&restart_daemon_argv())
        .map_err(|err| format!("{alias}: rustynetd restart after the reboot: {err}"))?;
    if !output.success {
        if daemon_unit_absent(&output.stderr) {
            return Err(format!(
                "{alias}: no rustynetd unit after the reboot; the guest cannot be verified"
            ));
        }
        return Err(format!(
            "{alias}: rustynetd restart failed after the reboot (start limit still latched?): {}",
            output.stderr.trim()
        ));
    }
    poll_daemon_active(runner, alias, DAEMON_ACTIVE_POLL_ATTEMPTS, sleep)
}

/// Require a wireguard handshake fresh enough to prove the rebooted node
/// re-keyed after the reboot (review finding 2): the stage's two-hop and
/// DNS-refresh checks run skipped without entry/second-client arguments, so
/// without this a daemon that came up with NO working mesh would pass.
fn assert_fresh_wg_handshake(
    runner: &dyn NetLeafRunner,
    alias: &str,
    now_unix: u64,
) -> Result<(), String> {
    let output = runner
        .run(&["sudo", "-n", "wg", "show", "all", "latest-handshakes"])
        .map_err(|err| format!("{alias}: wg handshake probe: {err}"))?;
    if !output.success {
        return Err(format!(
            "{alias}: wg show all latest-handshakes failed: {}",
            output.stderr.trim()
        ));
    }
    let freshest = output
        .stdout
        .lines()
        .filter_map(|line| line.split_whitespace().last())
        .filter_map(|field| field.parse::<u64>().ok())
        .max();
    match freshest {
        Some(timestamp) if now_unix.saturating_sub(timestamp) <= WG_HANDSHAKE_MAX_AGE_SECS => {
            Ok(())
        }
        Some(timestamp) => Err(format!(
            "{alias}: no fresh wireguard handshake after the reboot (latest handshake \
             {timestamp}, now {now_unix}; the mesh did not re-key within \
             {WG_HANDSHAKE_MAX_AGE_SECS}s)"
        )),
        None => assert_fresh_daemon_handshake(runner, alias, now_unix),
    }
}

/// The daemon-reported handshake evidence, used ONLY when kernel `wg` printed
/// no handshake line at all.
///
/// The `linux-wireguard-userspace-shared` backend keeps WireGuard state inside
/// `rustynetd` (a TUN device, no kernel wg interface), so `wg show all
/// latest-handshakes` is empty on a perfectly healthy mesh (katana-xnet-66). The
/// daemon is asked which backend it is and for the freshest live handshake it
/// itself measured:
/// - `transport_socket_identity_state=authoritative_backend_shared_transport`
///   (only a backend that owns the UDP socket reports it) means userspace-shared;
///   then `path_latest_live_handshake_unix=<unix>` is the evidence and the SAME
///   [`WG_HANDSHAKE_MAX_AGE_SECS`] rule applies. The daemon only fills that
///   field from a peer whose handshake it saw fresh, `none` means no live peer.
/// - `blocked_backend_opaque_socket` means the kernel backend: kernel `wg` was
///   the authority and it saw nothing, so the original failure stands.
/// - anything else (or no answer) is an unknown backend and fails closed;
///   nothing is guessed from the orchestrator's `--linux-backend`.
///
/// A stale kernel handshake never reaches this function, so the daemon cannot
/// rescue a mesh that kernel `wg` shows as not re-keyed.
fn assert_fresh_daemon_handshake(
    runner: &dyn NetLeafRunner,
    alias: &str,
    now_unix: u64,
) -> Result<(), String> {
    let no_handshakes = |detail: &str| {
        format!(
            "{alias}: wg reports no handshakes at all after the reboot; the mesh did not \
             re-converge ({detail})"
        )
    };
    let output = runner
        .run(&[
            "sudo",
            "-n",
            "env",
            "RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock",
            "rustynet",
            "netcheck",
        ])
        .map_err(|err| no_handshakes(&format!("daemon netcheck probe: {err}")))?;
    if !output.success {
        return Err(no_handshakes(&format!(
            "daemon netcheck failed: {}",
            output.stderr.trim()
        )));
    }
    let field = |key: &str| {
        output
            .stdout
            .split_whitespace()
            .find_map(|token| token.strip_prefix(key))
    };
    match field("transport_socket_identity_state=") {
        Some("authoritative_backend_shared_transport") => {}
        Some("blocked_backend_opaque_socket") => {
            return Err(no_handshakes(
                "kernel wireguard backend, kernel wg is the authority",
            ));
        }
        other => {
            return Err(no_handshakes(&format!(
                "cannot tell which wireguard backend this is (transport_socket_identity_state \
                 {other:?}); failing closed"
            )));
        }
    }
    let timestamp = match field("path_latest_live_handshake_unix=") {
        Some(raw) if !raw.is_empty() && raw.bytes().all(|b| b.is_ascii_digit()) => raw
            .parse::<u64>()
            .map_err(|_| no_handshakes("unparseable daemon handshake timestamp"))?,
        Some("none") => {
            return Err(no_handshakes(
                "userspace-shared daemon reports no live peer handshake",
            ));
        }
        other => {
            return Err(no_handshakes(&format!(
                "daemon netcheck carries no usable path_latest_live_handshake_unix ({other:?})"
            )));
        }
    };
    if now_unix.saturating_sub(timestamp) <= WG_HANDSHAKE_MAX_AGE_SECS {
        Ok(())
    } else {
        Err(format!(
            "{alias}: no fresh wireguard handshake after the reboot (daemon-reported latest \
             handshake {timestamp}, now {now_unix}; the mesh did not re-key within \
             {WG_HANDSHAKE_MAX_AGE_SECS}s)"
        ))
    }
}

/// Recover and VERIFY every rebooted guest (review findings 1 + 2). For
/// each rebooted alias: clear the start-limit latch, restart `rustynetd`,
/// boundedly poll `is-active` to a stable `active`, then require a fresh
/// wireguard handshake. A probe that cannot run, a unit that never reaches
/// active within the bound, or a stale handshake is a failure naming the
/// alias — the stage must fail closed, never skip.
fn recover_and_verify_rebooted_guests(
    runners: &BTreeMap<String, &dyn NetLeafRunner>,
    rebooted: &[&str],
    now_unix: u64,
    sleep: &dyn Fn(std::time::Duration),
) -> Result<(), String> {
    let mut errors = Vec::new();
    for alias in rebooted {
        let Some(&runner) = runners.get(*alias) else {
            errors.push(format!(
                "{alias}: no leaf runner to recover rustynetd after the reboot"
            ));
            continue;
        };
        if let Err(err) = recover_daemon_after_reboot(runner, alias, sleep) {
            errors.push(err);
            continue;
        }
        if let Err(err) = assert_fresh_wg_handshake(runner, alias, now_unix) {
            errors.push(err);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "rebooted-node recovery failed: {}",
            errors.join("; ")
        ))
    }
}

/// The reboot-recovery stage's substrate glue: re-provision the persisted
/// overlay for the nodes the binary rebooted, recover their daemons
/// (reset-failed + restart + bounded `is-active` poll), require a fresh WG
/// handshake, and only then record the evidence line. A run without a
/// provisioned substrate is a no-op pass (nothing was rebooted INTO an
/// overlay-dependent state).
pub(crate) fn reprovision_and_verify_after_reboot(
    ctx: &mut OrchestrationContext,
    rebooted: &[&str],
) -> Result<(), String> {
    let provisioned = ctx
        .substrate_record
        .as_ref()
        .is_some_and(|record| record.provisioned);
    if !provisioned {
        return Ok(());
    }
    let stage = StageId::LiveRebootRecoveryValidation.as_str();
    let topology = substrate_topology_from_ctx(ctx)?;
    let runners = build_remote_runners(ctx, stage)?;
    let refs = runner_refs(&runners);
    let report_dir = ctx.report_dir.clone();
    reprovision_and_verify_after_reboot_with(
        ctx,
        &topology,
        rebooted,
        &refs,
        &|line| {
            crate::vm_lab::orchestrator::evidence::append_stage_evidence_line(
                &report_dir,
                stage,
                line,
            )
        },
        &|duration| std::thread::sleep(duration),
    )
}

/// The injectable core of the stage glue: the same behavior as
/// [`reprovision_and_verify_after_reboot`] with the leaf runners, the
/// evidence writer and the poll sleep injected, so mock tests can drive the
/// provisioned path end to end (review required fix 2: the glue must be
/// witnessed, not just the skip path).
pub(crate) fn reprovision_and_verify_after_reboot_with(
    ctx: &mut OrchestrationContext,
    topology: &SubstrateTopology,
    rebooted: &[&str],
    runners: &BTreeMap<String, &dyn NetLeafRunner>,
    record_evidence: &dyn Fn(&str) -> Result<(), String>,
    sleep: &dyn Fn(std::time::Duration),
) -> Result<(), String> {
    let provisioned = ctx
        .substrate_record
        .as_ref()
        .is_some_and(|record| record.provisioned);
    if !provisioned {
        return Ok(());
    }
    reprovision_substrate_after_guest_reboot(ctx, topology, runners, rebooted)?;
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs())
        // A clock before the epoch makes every handshake look stale: fail
        // closed rather than skip the gate.
        .unwrap_or(0);
    recover_and_verify_rebooted_guests(runners, rebooted, now_unix, sleep)?;
    let overlay_nodes: Vec<&str> = topology.nodes.keys().map(String::as_str).collect();
    // Evidence ONLY after every check passed, and only claims that are true
    // at write time (review finding 5): the old line logged
    // `daemon_active=<csv>` BEFORE the assertion ran, so a failing run
    // recorded a claim its daemons were active. The two-hop and DNS-refresh
    // post-reboot checks stay skipped for this stage (it passes no
    // entry/second-client arguments), so they are marked not-verified here
    // instead of silently omitted (review finding 2).
    record_evidence(&format!(
        "substrate re-provisioned after guest reboot: overlay_nodes={} rebooted={} \
         daemon_active=restarted-and-verified:{} wg_handshake_fresh=verified:{} \
         post_reboot_twohop=not-verified post_reboot_dns_refresh=not-verified",
        overlay_nodes.join(","),
        rebooted.join(","),
        rebooted.join(","),
        rebooted.join(",")
    ))?;
    Ok(())
}

/// Provision the topology-level substrate BEFORE `collect_pubkeys` so overlay
/// addresses (not raw cross-LAN-unroutable underlay IPs) become the recorded
/// peer endpoints. A complete no-op pass unless `--cross-network-substrate
/// vxlan` is selected — the default netns substrate provisions nothing here
/// and existing single-LAN runs are unaffected.
pub struct CrossNetworkSubstrateSetupStage {
    options: CrossNetworkOptions,
}

impl CrossNetworkSubstrateSetupStage {
    pub fn new(options: CrossNetworkOptions) -> Self {
        Self { options }
    }

    /// The provider-driving half, parameterized over runners so it is
    /// unit-testable with `MockLeafRunner`. `execute` supplies real
    /// SSH-backed runners.
    fn provision(
        ctx: &mut OrchestrationContext,
        provider: &dyn CrossNetworkSubstrateProvider,
        topology: &SubstrateTopology,
        runners: &BTreeMap<String, &dyn NetLeafRunner>,
    ) -> StageOutcome {
        let plan = match plan_overlay(topology) {
            Ok(plan) => plan,
            Err(err) => return StageOutcome::Failed(err),
        };
        let digest = topology_digest(provider.id(), topology, plan.as_ref());
        if let Err(err) = check_record_against_request(
            ctx.substrate_record.as_ref(),
            Some(provider.id()),
            Some(&digest),
        ) {
            return StageOutcome::Failed(err);
        }
        // Preflight the daemon's `lab-substrate` capability BEFORE anything
        // is provisioned (design D). This is the earliest substrate-aware,
        // guest-reachable gate: the generic preflight stage knows nothing of
        // substrates, and the cross-network preflight stage only runs after
        // the live topology exists. A guest whose rustynetd lacks the
        // feature must stop the run here — half the mesh transit would
        // otherwise silently never come up.
        if let Some(plan) = plan.as_ref() {
            for alias in plan.overlay_ips.keys() {
                let runner = match VxlanSubstrateProvider::runner_for(runners, alias) {
                    Ok(runner) => runner,
                    Err(err) => return StageOutcome::Failed(err),
                };
                if !VxlanSubstrateProvider::guest_substrate_capability(runner) {
                    return StageOutcome::Failed(substrate_capability_refusal(alias));
                }
            }
        }
        match provider.setup(topology, runners) {
            Ok(handle) => {
                // The witness must describe the handle ACTUALLY returned, not
                // the requested topology: a vxlan setup whose participants
                // all share one underlay /24 provisions no overlay, and
                // witnessing that as provisioned=true would lie (a102
                // CORRECTION 2).
                let provisioned = handle.record.provisioned;
                let overlay_nodes = handle.record.participants.len();
                ctx.substrate_record = Some(handle.record.clone());
                ctx.substrate = Some(handle);
                // QH-83: the witness is written on EVERY pass path and a
                // write failure fails the stage.
                match Self::write_provision_witness(
                    &ctx.report_dir,
                    provider.id(),
                    provisioned,
                    overlay_nodes,
                ) {
                    Ok(()) => StageOutcome::Passed,
                    Err(err) => {
                        StageOutcome::Failed(format!("substrate witness write failed: {err}"))
                    }
                }
            }
            Err(failure) => {
                // Keep the partial state so the always-run teardown removes
                // exactly what was created before the failure.
                ctx.substrate_record = Some(failure.partial.record.clone());
                ctx.substrate = Some(failure.partial);
                StageOutcome::Failed(format!(
                    "{} substrate setup failed (partial state recorded for teardown): {}",
                    provider.id(),
                    failure.message
                ))
            }
        }
    }
    /// QH-83 witness for the no-overlay pass path: the runner demotes a
    /// declared StageLog stage whose log is empty, so the seam's no-op pass
    /// still records what it checked (record/request match, zero overlay
    /// nodes) and the scope stays auditable.
    fn write_no_overlay_witness(
        report_dir: &std::path::Path,
        assignments: usize,
    ) -> Result<(), String> {
        crate::vm_lab::orchestrator::evidence::append_stage_evidence_line(
            report_dir,
            StageId::CrossNetworkSubstrateSetup.as_str(),
            &format!(
                "substrate_setup=no-overlay record_match=ok overlay_nodes=0 assignments={assignments}"
            ),
        )
    }

    /// QH-83 witness for the overlay-provisioning pass path. It reports the
    /// setup that was ACTUALLY performed, taken from the returned handle: a
    /// no-overlay pass (every participant inside one underlay /24) is still
    /// a pass, but the witness must say `provisioned=false overlay_nodes=0`
    /// and name the reason instead of claiming nodes that were never
    /// provisioned.
    fn write_provision_witness(
        report_dir: &std::path::Path,
        provider_id: &str,
        provisioned: bool,
        overlay_nodes: usize,
    ) -> Result<(), String> {
        let line = if provisioned {
            format!("substrate_setup={provider_id} provisioned=true overlay_nodes={overlay_nodes}")
        } else {
            format!(
                "substrate_setup={provider_id} provisioned=false overlay_nodes={overlay_nodes} \
                 no-overlay: all participants share one underlay /24"
            )
        };
        crate::vm_lab::orchestrator::evidence::append_stage_evidence_line(
            report_dir,
            StageId::CrossNetworkSubstrateSetup.as_str(),
            &line,
        )
    }
}

impl OrchestrationStage for CrossNetworkSubstrateSetupStage {
    fn id(&self) -> StageId {
        StageId::CrossNetworkSubstrateSetup
    }
    fn name(&self) -> &str {
        "cross_network_substrate_setup"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::BootstrapHosts]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let provider = match topology_level_seam(self.options.substrate) {
            TopologySeam::Provisions(provider) => provider,
            TopologySeam::NoOverlay(_reason) => {
                // No overlay-provisioning substrate requested: pass through
                // untouched — UNLESS a resumed context says one was
                // provisioned, which is a provenance mismatch and fails
                // closed.
                return match check_record_against_request(ctx.substrate_record.as_ref(), None, None)
                {
                    Ok(()) => {
                        // QH-83: the witness is written on EVERY pass path
                        // and a write failure fails the stage.
                        match Self::write_no_overlay_witness(&ctx.report_dir, ctx.assignments.len())
                        {
                            Ok(()) => StageOutcome::Passed,
                            Err(err) => StageOutcome::Failed(format!(
                                "substrate witness write failed: {err}"
                            )),
                        }
                    }
                    Err(err) => StageOutcome::Failed(err),
                };
            }
        };
        let topology = match substrate_topology_from_ctx(ctx) {
            Ok(topology) => topology,
            Err(err) => return StageOutcome::Failed(err),
        };
        // The vxlan leaf ops are Linux `ip`/`bridge`; a non-Linux guest in an
        // overlay-needing topology cannot be silently excluded (its endpoints
        // would stay unroutable), so fail closed until per-OS leaf ops exist.
        let overlay_needed = match plan_overlay(&topology) {
            Err(err) => return StageOutcome::Failed(err),
            Ok(None) => false,
            Ok(Some(_)) => {
                for assignment in &ctx.assignments {
                    let platform = ctx
                        .adapters
                        .get(assignment.alias.as_str())
                        .map(|adapter| adapter.platform());
                    if platform != Some(crate::vm_lab::VmGuestPlatform::Linux) {
                        return StageOutcome::Failed(format!(
                            "the {} topology substrate supports only Linux guests today; \
                             '{}' is {:?}",
                            provider.id(),
                            assignment.alias,
                            platform
                        ));
                    }
                }
                true
            }
        };
        let runners = match build_remote_runners(ctx, "cross_network_substrate_setup") {
            Ok(runners) => runners,
            Err(err) => return StageOutcome::Failed(err),
        };
        // The vxlan data path rides the guest kernel's vxlan module; a guest
        // that cannot load it would fail later mid-topology with an opaque
        // RTNETLINK error. `modprobe -n` is the dry-run probe — it answers
        // "could this kernel set vxlan up" (module loadable or builtin) and
        // changes nothing — and it runs per topology participant so the
        // failure NAMES the guests that cannot host the overlay instead of
        // failing the first `ip link add` with a bare errno.
        if overlay_needed {
            for (alias, runner) in &runners {
                if !topology.nodes.contains_key(alias) {
                    continue;
                }
                if super::scenario::run_root(runner, &["modprobe", "-n", "vxlan"]).is_err() {
                    return StageOutcome::Failed(format!(
                        "the {} substrate needs kernel vxlan support, but guest '{}' cannot \
                         provision it (`modprobe -n vxlan` failed): install the module \
                         (e.g. linux-modules-extra) or use a guest whose kernel ships it",
                        provider.id(),
                        alias
                    ));
                }
            }
        }
        let refs = runner_refs(&runners);
        Self::provision(ctx, provider.as_ref(), &topology, &refs)
    }
}

/// Remove every vxlan link the substrate created — even after a partial
/// setup or an earlier stage failure (`always_run`), and even after a resume
/// where only the persisted record survives. Failure to remove is a stage
/// FAILURE (possible residue), never silent.
pub struct CrossNetworkSubstrateTeardownStage {
    options: CrossNetworkOptions,
}

impl CrossNetworkSubstrateTeardownStage {
    pub fn new(options: CrossNetworkOptions) -> Self {
        Self { options }
    }

    fn teardown_with(
        ctx: &mut OrchestrationContext,
        runners: &BTreeMap<String, &dyn NetLeafRunner>,
        requested_id: Option<&str>,
    ) -> StageOutcome {
        let Some(record) = ctx.substrate_record.clone() else {
            return StageOutcome::Passed;
        };
        if let Err(err) = check_record_against_request(Some(&record), requested_id, None) {
            return StageOutcome::Failed(err);
        }
        if !record.provisioned {
            // QH-83: this pass removes nothing, and the evidence line must
            // say so — a bare pass over a record that provisioned no overlay
            // would read as a removal. A witness write failure fails the
            // stage, like every other pass path.
            return match crate::vm_lab::orchestrator::evidence::append_stage_evidence_line(
                &ctx.report_dir,
                StageId::CrossNetworkSubstrateTeardown.as_str(),
                "substrate_teardown=nothing-to-remove (not provisioned)",
            ) {
                Ok(()) => StageOutcome::Passed,
                Err(err) => {
                    StageOutcome::Failed(format!("substrate teardown witness write failed: {err}"))
                }
            };
        }
        // Dispatch on what the RECORD says was provisioned, not on what this
        // run selected: an unknown id means we cannot remove it correctly, and
        // guessing would report a pass over real residue.
        let Some(provider) = provider_for_record(&record.substrate_id) else {
            return StageOutcome::Failed(format!(
                "no teardown provider for persisted substrate '{}'; refusing to report a pass \
                 over possible residue",
                record.substrate_id
            ));
        };
        // The live handle when we have it (exact created-link list, covers
        // partial setup); otherwise a record-derived handle (resume case).
        let handle = ctx.substrate.clone().unwrap_or_else(|| SubstrateHandle {
            record: record.clone(),
            overlay_ips: BTreeMap::new(),
            underlay_ips: BTreeMap::new(),
            created_resources: Vec::new(),
        });
        match provider.teardown(&handle, runners) {
            Ok(()) => {
                ctx.substrate = None;
                StageOutcome::Passed
            }
            Err(err) => StageOutcome::Failed(err),
        }
    }
}

impl OrchestrationStage for CrossNetworkSubstrateTeardownStage {
    fn id(&self) -> StageId {
        StageId::CrossNetworkSubstrateTeardown
    }
    fn name(&self) -> &str {
        "cross_network_substrate_teardown"
    }
    fn dependencies(&self) -> &[StageId] {
        // Teardown is a `finally` block like FinalCleanupStage: ordered by
        // catalog position (just before `cleanup`), gated on nothing.
        &[]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }

    /// Overlay residue on the guests is release-blocking exactly like exit-NAT
    /// residue: teardown must run even when an earlier stage failed.
    fn always_run(&self) -> bool {
        true
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let requested = match topology_level_seam(self.options.substrate) {
            TopologySeam::Provisions(provider) => Some(provider),
            TopologySeam::NoOverlay(_) => None,
        };
        let requested_id = requested.as_ref().map(|provider| provider.id());
        if ctx.substrate_record.is_none() {
            return StageOutcome::Passed;
        }
        let runners = match build_remote_runners(ctx, "cross_network_substrate_teardown") {
            Ok(runners) => runners,
            Err(err) => return StageOutcome::Failed(err),
        };
        let refs = runner_refs(&runners);
        Self::teardown_with(ctx, &refs, requested_id)
    }
}

#[cfg(test)]
pub(crate) mod mock {
    use super::{LeafOutput, NetLeafRunner};
    use std::sync::Mutex;

    /// Scriptable in-memory runner: records every argv, fails (exit status or
    /// transport) at the scripted call indexes, and can script stdout either
    /// by call index or by an argv substring.
    #[derive(Default)]
    pub struct MockLeafRunner {
        pub calls: Mutex<Vec<Vec<String>>>,
        /// 0-based call indexes that return `success: false`.
        pub fail_on: Vec<usize>,
        /// 0-based call indexes that return `Err` (transport failure).
        pub transport_error_on: Vec<usize>,
        /// stderr text attached to failing calls.
        pub failure_stderr: String,
        /// stdout keyed by 0-based call index (checked first).
        pub stdout_for: Vec<(usize, String)>,
        /// stdout keyed by a substring of the space-joined argv — how a test
        /// scripts "whatever call runs `nat-classify` answers this", without
        /// having to count the calls before it.
        pub stdout_by_match: Vec<(String, String)>,
        /// stdout SEQUENCES keyed by an argv substring: the nth matching call
        /// gets `seq[n]` (clamped to the last entry) — how a test scripts
        /// `is-active` answering `activating`, then `active`, then `active`.
        pub stdout_seq_by_match: Vec<(String, Vec<String>)>,
    }

    impl MockLeafRunner {
        fn scripted_stdout(&self, index: usize, argv: &[&str]) -> String {
            if let Some((_, text)) = self.stdout_for.iter().find(|(at, _)| *at == index) {
                return text.clone();
            }
            let joined = argv.join(" ");
            if let Some((needle, seq)) = self
                .stdout_seq_by_match
                .iter()
                .find(|(needle, _)| joined.contains(needle.as_str()))
            {
                if !seq.is_empty() {
                    let answered = self.calls.lock().expect("mock runner lock")[..index]
                        .iter()
                        .filter(|call| call.join(" ").contains(needle.as_str()))
                        .count();
                    return seq[answered.min(seq.len() - 1)].clone();
                }
            }
            self.stdout_by_match
                .iter()
                .find(|(needle, _)| joined.contains(needle.as_str()))
                .map(|(_, text)| text.clone())
                .unwrap_or_default()
        }
    }

    impl NetLeafRunner for MockLeafRunner {
        fn run(&self, argv: &[&str]) -> Result<LeafOutput, String> {
            let mut calls = self.calls.lock().expect("mock runner lock");
            let index = calls.len();
            calls.push(argv.iter().map(|s| (*s).to_owned()).collect());
            drop(calls);
            if self.transport_error_on.contains(&index) {
                return Err(format!("mock transport failure at call {index}"));
            }
            Ok(LeafOutput {
                success: !self.fail_on.contains(&index),
                stdout: self.scripted_stdout(index, argv),
                stderr: if self.fail_on.contains(&index) {
                    self.failure_stderr.clone()
                } else {
                    String::new()
                },
            })
        }
    }

    impl MockLeafRunner {
        pub fn recorded(&self) -> Vec<Vec<String>> {
            self.calls.lock().expect("mock runner lock").clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options_with(substrate: CrossNetworkSubstrate) -> CrossNetworkOptions {
        CrossNetworkOptions {
            substrate,
            ..CrossNetworkOptions::default()
        }
    }

    fn empty_ctx() -> OrchestrationContext {
        OrchestrationContext::new(Vec::new(), std::env::temp_dir(), "net".to_owned())
    }

    fn vxlan_record(provisioned: bool) -> SubstrateRecord {
        SubstrateRecord {
            substrate_id: "vxlan".to_owned(),
            topology_digest: "digest".to_owned(),
            provisioned,
            participants: vec!["a".to_owned()],
        }
    }

    /// Invariant (a): the default (netns) substrate makes both lifecycle
    /// stages complete no-ops that PASS — existing single-LAN runs are
    /// untouched (no record written, no endpoint change, no leaf command).
    #[test]
    fn setup_and_teardown_are_no_op_passes_without_an_overlay_substrate() {
        let mut ctx = empty_ctx();
        let setup =
            CrossNetworkSubstrateSetupStage::new(options_with(CrossNetworkSubstrate::Netns));
        assert_eq!(setup.execute(&mut ctx), StageOutcome::Passed);
        assert!(ctx.substrate.is_none());
        assert!(ctx.substrate_record.is_none());
        assert!(ctx.endpoints.is_empty());

        let teardown =
            CrossNetworkSubstrateTeardownStage::new(options_with(CrossNetworkSubstrate::Netns));
        assert_eq!(teardown.execute(&mut ctx), StageOutcome::Passed);
    }

    /// Invariant (c): a resumed context recording a provisioned substrate
    /// while this run requests none is a provenance mismatch — hard failure,
    /// in BOTH lifecycle stages.
    #[test]
    fn resume_with_a_substrate_mismatch_fails_closed() {
        let mut ctx = empty_ctx();
        ctx.substrate_record = Some(vxlan_record(true));
        let setup =
            CrossNetworkSubstrateSetupStage::new(options_with(CrossNetworkSubstrate::Netns));
        let outcome = setup.execute(&mut ctx);
        assert!(
            matches!(outcome, StageOutcome::Failed(ref msg) if msg.contains("provenance mismatch")),
            "{outcome:?}"
        );

        let teardown =
            CrossNetworkSubstrateTeardownStage::new(options_with(CrossNetworkSubstrate::Netns));
        let outcome = teardown.execute(&mut ctx);
        assert!(
            matches!(outcome, StageOutcome::Failed(ref msg) if msg.contains("provenance mismatch")),
            "{outcome:?}"
        );
    }

    /// Invariant (c), digest half: same substrate id but a changed topology
    /// (inventory moved under the resume) must fail closed, before any leaf
    /// command runs.
    #[test]
    fn resume_with_a_changed_topology_digest_fails_closed() {
        use mock::MockLeafRunner;
        let mut ctx = empty_ctx();
        let mut stale = vxlan_record(true);
        stale.topology_digest = "not-the-current-digest".to_owned();
        ctx.substrate_record = Some(stale);
        let a = MockLeafRunner::default();
        let b = MockLeafRunner::default();
        let runners = runner_map(&[("a", &a), ("b", &b)]);
        let topo = topology(&[("a", "192.168.64.10"), ("b", "192.168.0.30")]);
        let outcome = CrossNetworkSubstrateSetupStage::provision(
            &mut ctx,
            &VxlanSubstrateProvider,
            &topo,
            &runners,
        );
        assert!(
            matches!(outcome, StageOutcome::Failed(ref msg) if msg.contains("topology mismatch")),
            "{outcome:?}"
        );
        assert!(a.recorded().is_empty(), "no leaf command may run");
        assert!(b.recorded().is_empty());
    }

    /// Happy path through the stage seam: provision records the handle +
    /// record on the context; teardown then removes the created links and
    /// drains the handle.
    #[test]
    fn provision_then_teardown_round_trips_through_the_context() {
        use mock::MockLeafRunner;
        let mut ctx = empty_ctx();
        let a = substrate_ready_runner();
        let b = substrate_ready_runner();
        let runners = runner_map(&[("a", &a), ("b", &b)]);
        let topo = topology(&[("a", "192.168.64.10"), ("b", "192.168.0.30")]);
        assert_eq!(
            CrossNetworkSubstrateSetupStage::provision(
                &mut ctx,
                &VxlanSubstrateProvider,
                &topo,
                &runners
            ),
            StageOutcome::Passed
        );
        let handle = ctx.substrate.as_ref().expect("handle stored");
        assert!(handle.record.provisioned);
        assert_eq!(handle.created_resources.len(), 2);
        assert_eq!(
            ctx.substrate_record.as_ref().map(|r| r.provisioned),
            Some(true)
        );

        let td_a = MockLeafRunner::default();
        let td_b = MockLeafRunner::default();
        let td_runners = runner_map(&[("a", &td_a), ("b", &td_b)]);
        assert_eq!(
            CrossNetworkSubstrateTeardownStage::teardown_with(&mut ctx, &td_runners, Some("vxlan")),
            StageOutcome::Passed
        );
        assert!(ctx.substrate.is_none(), "teardown drains the live handle");
        // Per participant: link removal, egress-pin revert, attestation
        // removal, then the nft + attestation residue probes.
        let expected_td_len = 2 + substrate_teardown_head().len() + substrate_teardown_tail().len();
        assert_eq!(td_a.recorded().len(), expected_td_len);
        assert_eq!(td_b.recorded().len(), expected_td_len);
    }

    /// Invariant (d) at the stage seam: after a PARTIAL setup the context
    /// still carries the created links, and teardown issues a removal per
    /// created interface.
    #[test]
    fn teardown_after_partial_setup_removes_every_created_interface() {
        use mock::MockLeafRunner;
        let mut ctx = empty_ctx();
        // Node "a" provisions fully (its attestation write included); node
        // "b"'s `ip link add` fails. Both must pass the provision gate's
        // capability probe first: probe = call 0, pre-delete = call 1, so the
        // link add is call 2.
        let a = substrate_ready_runner();
        let mut b = substrate_ready_runner();
        b.fail_on = vec![2];
        b.failure_stderr = "RTNETLINK answers: Operation not permitted".to_owned();
        let runners = runner_map(&[("a", &a), ("b", &b)]);
        let topo = topology(&[("a", "192.168.0.30"), ("b", "192.168.64.10")]);
        let outcome = CrossNetworkSubstrateSetupStage::provision(
            &mut ctx,
            &VxlanSubstrateProvider,
            &topo,
            &runners,
        );
        assert!(matches!(outcome, StageOutcome::Failed(_)), "{outcome:?}");
        assert_eq!(
            ctx.substrate
                .as_ref()
                .map(|handle| handle.created_resources.clone()),
            Some(vec![CreatedResource::link("a", VXLAN_LINK_NAME)]),
            "the partial handle must survive the failure for teardown"
        );

        let td_a = MockLeafRunner::default();
        let td_runners = runner_map(&[("a", &td_a)]);
        assert_eq!(
            CrossNetworkSubstrateTeardownStage::teardown_with(&mut ctx, &td_runners, Some("vxlan")),
            StageOutcome::Passed
        );
        let mut expected: Vec<Vec<String>> = substrate_teardown_head()
            .into_iter()
            .map(|line| line.split(' ').map(str::to_owned).collect::<Vec<_>>())
            .collect();
        expected.extend(vec![
            vec![
                "sudo".to_owned(),
                "-n".to_owned(),
                "ip".to_owned(),
                "link".to_owned(),
                "del".to_owned(),
                VXLAN_LINK_NAME.to_owned(),
            ],
            vec![
                "sudo".to_owned(),
                "-n".to_owned(),
                "sed".to_owned(),
                "-i".to_owned(),
                "-e".to_owned(),
                format!("/^RUSTYNET_EGRESS_INTERFACE={VXLAN_LINK_NAME}$/d"),
                "-e".to_owned(),
                format!("/^RUSTYNET_EGRESS_INTERFACE={VXLAN_SITE_LAN_IF}$/d"),
                DAEMON_ENV_FILE.to_owned(),
            ],
        ]);
        expected.extend(
            substrate_teardown_tail()
                .into_iter()
                .map(|line| line.split(' ').map(str::to_owned).collect::<Vec<_>>()),
        );
        assert_eq!(
            td_a.recorded(),
            expected,
            "attestation removal + daemon restart, then one removal per created \
             interface, then the egress-pin revert, then the residue probes"
        );
    }

    /// The residue that cost two live-lab runs: while the overlay is up, the
    /// route to the selected exit endpoint leaves through the vxlan link, so
    /// `ops install-systemd` derives THAT link as the egress interface and pins
    /// it in `/etc/default/rustynetd`. Deleting the link without deleting the
    /// pin leaves a value naming a device that no longer exists, and the next
    /// ordinary install fails `egress interface does not exist`. Teardown owns
    /// reverting what its overlay caused to be written.
    #[test]
    fn teardown_reverts_the_egress_pin_the_overlay_caused_to_be_written() {
        use mock::MockLeafRunner;
        let mut ctx = empty_ctx();
        ctx.substrate_record = Some(SubstrateRecord {
            substrate_id: "vxlan".to_owned(),
            topology_digest: "digest".to_owned(),
            provisioned: true,
            participants: vec!["a".to_owned()],
        });
        let td_a = MockLeafRunner::default();
        let td_runners = runner_map(&[("a", &td_a)]);
        assert_eq!(
            CrossNetworkSubstrateTeardownStage::teardown_with(&mut ctx, &td_runners, Some("vxlan")),
            StageOutcome::Passed
        );
        let recorded = td_a.recorded();
        let revert = recorded
            .iter()
            .find(|argv| argv.iter().any(|element| element == "sed"))
            .expect("teardown must revert the egress pin");
        assert!(
            revert.contains(&format!("/^RUSTYNET_EGRESS_INTERFACE={VXLAN_LINK_NAME}$/d")),
            "{revert:?}"
        );
        assert!(revert.contains(&DAEMON_ENV_FILE.to_owned()), "{revert:?}");
        // Only the value line is deleted. The provenance marker is inert
        // without a value to describe, and the next install rewrites the file
        // wholesale; deleting it here could not be made conditional on the
        // value line actually having matched.
        assert!(
            !revert
                .iter()
                .any(|element| element.contains("RUSTYNET_EGRESS_INTERFACE_SOURCE")),
            "{revert:?}"
        );
    }

    /// A guest whose env file was never written is not residue: `sed -i` on a
    /// missing file is the idempotent success case, exactly as `ip link del` on
    /// an already-removed device is.
    #[test]
    fn a_guest_with_no_daemon_env_file_is_not_reported_as_residue() {
        use mock::MockLeafRunner;
        let mut ctx = empty_ctx();
        ctx.substrate_record = Some(SubstrateRecord {
            substrate_id: "vxlan".to_owned(),
            topology_digest: "digest".to_owned(),
            provisioned: true,
            participants: vec!["a".to_owned()],
        });
        // Calls 0/1/2 are the attestation removal + limit reset + daemon
        // restart, 3..=5 the three record-derived removals; call 6 is the
        // revert.
        let td_a = MockLeafRunner {
            fail_on: vec![6],
            failure_stderr: "sed: can't read /etc/default/rustynetd: No such file or directory"
                .to_owned(),
            ..MockLeafRunner::default()
        };
        let td_runners = runner_map(&[("a", &td_a)]);
        assert_eq!(
            CrossNetworkSubstrateTeardownStage::teardown_with(&mut ctx, &td_runners, Some("vxlan")),
            StageOutcome::Passed
        );
    }

    /// A revert that fails for any other reason is possible residue and must
    /// fail the stage, never pass silently.
    #[test]
    fn a_failed_egress_pin_revert_fails_the_teardown_stage() {
        use mock::MockLeafRunner;
        let mut ctx = empty_ctx();
        ctx.substrate_record = Some(SubstrateRecord {
            substrate_id: "vxlan".to_owned(),
            topology_digest: "digest".to_owned(),
            provisioned: true,
            participants: vec!["a".to_owned()],
        });
        let td_a = MockLeafRunner {
            fail_on: vec![6],
            failure_stderr: "sed: couldn't open temporary file: Read-only file system".to_owned(),
            ..MockLeafRunner::default()
        };
        let td_runners = runner_map(&[("a", &td_a)]);
        let outcome =
            CrossNetworkSubstrateTeardownStage::teardown_with(&mut ctx, &td_runners, Some("vxlan"));
        assert!(
            matches!(outcome, StageOutcome::Failed(ref msg) if msg.contains("egress interface pin")),
            "{outcome:?}"
        );
    }

    /// The link name is interpolated into a `sed` regular expression, so the
    /// character set is allowlisted rather than trusted. A metacharacter would
    /// silently widen the deletion to lines it was never meant to touch.
    #[test]
    fn egress_pin_deletion_refuses_a_regex_unsafe_interface_name() {
        assert_eq!(
            egress_pin_delete_program(VXLAN_LINK_NAME),
            Ok(format!("/^RUSTYNET_EGRESS_INTERFACE={VXLAN_LINK_NAME}$/d"))
        );
        for unsafe_name in ["", ".*", "eth0$/d;/^X=/d", "eth 0", "eth/0"] {
            assert!(
                egress_pin_delete_program(unsafe_name).is_err(),
                "accepted unsafe interface name {unsafe_name:?}"
            );
        }
    }

    #[test]
    fn check_record_against_request_covers_the_three_mismatch_axes() {
        let record = vxlan_record(true);
        assert!(check_record_against_request(None, None, None).is_ok());
        assert!(check_record_against_request(Some(&record), None, None).is_err());
        assert!(check_record_against_request(Some(&record), Some("netns"), None).is_err());
        assert!(check_record_against_request(Some(&record), Some("vxlan"), None).is_ok());
        assert!(check_record_against_request(Some(&record), Some("vxlan"), Some("digest")).is_ok());
        assert!(check_record_against_request(Some(&record), Some("vxlan"), Some("other")).is_err());
    }

    fn topology(pairs: &[(&str, &str)]) -> SubstrateTopology {
        SubstrateTopology {
            nodes: pairs
                .iter()
                .map(|(alias, ip)| ((*alias).to_owned(), ip.parse().expect("test ip")))
                .collect(),
        }
    }

    #[test]
    fn single_network_group_needs_no_overlay() {
        let plan = plan_overlay(&topology(&[("a", "192.168.64.10"), ("b", "192.168.64.11")]))
            .expect("plan");
        assert_eq!(plan, None, "one /24 group must plan no overlay");
    }

    #[test]
    fn two_groups_get_distinct_per_group_slash24s() {
        let plan = plan_overlay(&topology(&[
            ("utm-1", "192.168.64.10"),
            ("utm-2", "192.168.64.11"),
            ("lenovo-1", "192.168.0.30"),
            ("lenovo-2", "192.168.0.31"),
        ]))
        .expect("plan")
        .expect("two groups need an overlay");
        // Groups sort by underlay prefix: 192.168.0/24 first, 192.168.64/24 second.
        assert_eq!(
            plan.overlay_ips.get("lenovo-1").map(ToString::to_string),
            Some("172.20.10.2".to_owned())
        );
        assert_eq!(
            plan.overlay_ips.get("lenovo-2").map(ToString::to_string),
            Some("172.20.10.3".to_owned())
        );
        assert_eq!(
            plan.overlay_ips.get("utm-1").map(ToString::to_string),
            Some("172.20.20.2".to_owned())
        );
        assert_eq!(
            plan.overlay_ips.get("utm-2").map(ToString::to_string),
            Some("172.20.20.3".to_owned())
        );
        // All overlay addresses are unique.
        let unique: std::collections::HashSet<_> = plan.overlay_ips.values().collect();
        assert_eq!(unique.len(), plan.overlay_ips.len());
    }

    #[test]
    fn overlay_mac_is_locally_administered_and_unique_per_overlay_ip() {
        let a = overlay_mac(Ipv4Addr::new(172, 20, 10, 2));
        let b = overlay_mac(Ipv4Addr::new(172, 20, 20, 2));
        assert_eq!(a, "02:52:ac:14:0a:02");
        assert_eq!(b, "02:52:ac:14:14:02");
        assert_ne!(a, b, "distinct overlay IPs must yield distinct MACs");
    }

    #[test]
    fn topology_digest_changes_when_a_node_moves_network() {
        let before = topology(&[("a", "192.168.64.10"), ("b", "192.168.0.30")]);
        let after = topology(&[("a", "192.168.64.10"), ("b", "192.168.2.30")]);
        let plan_before = plan_overlay(&before).expect("plan").expect("overlay");
        let plan_after = plan_overlay(&after).expect("plan").expect("overlay");
        assert_ne!(
            topology_digest("vxlan", &before, Some(&plan_before)),
            topology_digest("vxlan", &after, Some(&plan_after)),
            "a changed underlay must change the digest so resume fails closed"
        );
    }

    #[test]
    fn argv_validation_rejects_control_chars_and_empty_elements() {
        assert!(validate_argv(&[]).is_err());
        assert!(validate_argv(&["ip", ""]).is_err());
        assert!(validate_argv(&["ip", "link\nadd"]).is_err());
        assert!(validate_argv(&["sudo", "-n", "ip", "link", "del", "rustynet-vx0"]).is_ok());
    }

    #[test]
    fn shell_quote_neutralises_single_quotes() {
        assert_eq!(shell_quote("plain"), "'plain'");
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
    }

    fn two_lan_topology() -> SubstrateTopology {
        topology(&[
            ("lenovo-1", "192.168.0.30"),
            ("utm-1", "192.168.64.10"),
            ("utm-2", "192.168.64.11"),
        ])
    }

    fn runner_map<'a>(
        runners: &[(&str, &'a mock::MockLeafRunner)],
    ) -> BTreeMap<String, &'a dyn NetLeafRunner> {
        runners
            .iter()
            .map(|(alias, runner)| ((*alias).to_owned(), *runner as &dyn NetLeafRunner))
            .collect()
    }

    #[test]
    fn vxlan_setup_provisions_link_fdb_mesh_addr_and_up_per_node() {
        let lenovo = route_answer_runner();
        let utm1 = route_answer_runner();
        let utm2 = route_answer_runner();
        let runners = runner_map(&[("lenovo-1", &lenovo), ("utm-1", &utm1), ("utm-2", &utm2)]);
        let handle = VxlanSubstrateProvider
            .setup(&two_lan_topology(), &runners)
            .expect("setup");

        assert!(handle.record.provisioned);
        assert_eq!(
            handle.record.participants,
            ["lenovo-1", "utm-1", "utm-2"],
            "every node participates"
        );
        assert_eq!(handle.created_resources.len(), 3);
        // Per node: del + add + 2 fdb + 2 addr (overlay + transit alias) + up
        // + route get + write = 9.
        let calls = lenovo.recorded();
        assert_eq!(calls.len(), 9);
        assert_eq!(
            calls[1],
            [
                "sudo",
                "-n",
                "ip",
                "link",
                "add",
                VXLAN_LINK_NAME,
                "address",
                // Unique per-node MAC derived from the overlay IP
                // (172.20.10.2): cloned guests share machine-id, so the
                // systemd-persistent default MAC collides and vxlan decap
                // self-drops every inner frame.
                "02:52:ac:14:0a:02",
                "type",
                "vxlan",
                "id",
                VXLAN_VNI,
                "local",
                "192.168.0.30",
                "dstport",
                VXLAN_DSTPORT,
                "srcport",
                VXLAN_SRCPORT_LOW,
                VXLAN_SRCPORT_HIGH,
                "nolearning"
            ]
        );
        // fdb mesh entries point at BOTH peers' underlay addresses.
        let fdb_dsts: Vec<&str> = calls[2..4]
            .iter()
            .map(|argv| argv.last().expect("dst").as_str())
            .collect();
        assert_eq!(fdb_dsts, ["192.168.64.10", "192.168.64.11"]);
        assert_eq!(
            calls[4],
            [
                "sudo",
                "-n",
                "ip",
                "addr",
                "replace",
                "172.20.10.2/16",
                "dev",
                VXLAN_LINK_NAME
            ]
        );
        // The deterministic transit alias rides the SAME device as a second
        // address: 172.20.10.2 → 198.18.10.2, /16, `replace` (idempotent).
        assert_eq!(
            calls[5],
            [
                "sudo",
                "-n",
                "ip",
                "addr",
                "replace",
                "198.18.10.2/16",
                "dev",
                VXLAN_LINK_NAME
            ]
        );
        assert_eq!(
            calls[6],
            ["sudo", "-n", "ip", "link", "set", VXLAN_LINK_NAME, "up"]
        );
        // The underlay interface is derived ON the guest from its own route
        // to the first peer, then attested with the full mesh peer list.
        assert_eq!(
            calls[7],
            ["sudo", "-n", "ip", "route", "get", "192.168.64.10"]
        );
        assert_eq!(
            calls[8],
            [
                "sudo",
                "-n",
                GUEST_RUSTYNET_CLI,
                "ops",
                "vm-lab-write-substrate-transit",
                "--overlay-interface",
                VXLAN_LINK_NAME,
                "--underlay-interface",
                "mgmt0",
                "--peer",
                "192.168.64.10",
                "--peer",
                "192.168.64.11"
            ]
        );
        // The handle carries BOTH address planes, keyed by alias.
        assert_eq!(
            handle.overlay_ips.get("utm-1").map(String::as_str),
            Some("172.20.20.2")
        );
        assert_eq!(
            handle.underlay_ips.get("utm-1").map(String::as_str),
            Some("192.168.64.10")
        );
        // And every participant attested (its write argv is on record).
        for runner in [&lenovo, &utm1, &utm2] {
            assert!(
                joined(runner)
                    .iter()
                    .any(|call| call.contains("vm-lab-write-substrate-transit")),
                "every participant must attest its transit"
            );
        }
    }

    #[test]
    fn vxlan_setup_failure_keeps_partial_created_resources_for_teardown() {
        use mock::MockLeafRunner;
        let lenovo = route_answer_runner();
        // Second node's `ip link add` (its call index 1, after the pre-delete)
        // fails.
        let utm1 = MockLeafRunner {
            fail_on: vec![1],
            failure_stderr: "RTNETLINK answers: Operation not permitted".to_owned(),
            ..MockLeafRunner::default()
        };
        let utm2 = MockLeafRunner::default();
        let runners = runner_map(&[("lenovo-1", &lenovo), ("utm-1", &utm1), ("utm-2", &utm2)]);
        let failure = VxlanSubstrateProvider
            .setup(&two_lan_topology(), &runners)
            .expect_err("half-provisioned setup must fail closed");
        assert!(failure.message.contains("utm-1"), "{}", failure.message);
        // The partial handle still lists the link the FIRST node created, so
        // the always-run teardown can remove it.
        assert_eq!(
            failure.partial.created_resources,
            [CreatedResource::link("lenovo-1", VXLAN_LINK_NAME)]
        );

        // Teardown after the partial setup issues one removal per created link.
        let lenovo_td = MockLeafRunner::default();
        let td_runners = runner_map(&[("lenovo-1", &lenovo_td)]);
        VxlanSubstrateProvider
            .teardown(&failure.partial, &td_runners)
            .expect("teardown of the partial state");
        let mut expected: Vec<Vec<String>> = substrate_teardown_head()
            .into_iter()
            .map(|line| line.split(' ').map(str::to_owned).collect::<Vec<_>>())
            .collect();
        expected.extend(vec![
            vec![
                "sudo".to_owned(),
                "-n".to_owned(),
                "ip".to_owned(),
                "link".to_owned(),
                "del".to_owned(),
                VXLAN_LINK_NAME.to_owned(),
            ],
            // The overlay also caused an egress pin to be written; teardown
            // reverts it on the same guest.
            vec![
                "sudo".to_owned(),
                "-n".to_owned(),
                "sed".to_owned(),
                "-i".to_owned(),
                "-e".to_owned(),
                format!("/^RUSTYNET_EGRESS_INTERFACE={VXLAN_LINK_NAME}$/d"),
                "-e".to_owned(),
                format!("/^RUSTYNET_EGRESS_INTERFACE={VXLAN_SITE_LAN_IF}$/d"),
                DAEMON_ENV_FILE.to_owned(),
            ],
        ]);
        expected.extend(
            substrate_teardown_tail()
                .into_iter()
                .map(|line| line.split(' ').map(str::to_owned).collect::<Vec<_>>()),
        );
        assert_eq!(lenovo_td.recorded(), expected);
    }

    #[test]
    fn vxlan_teardown_falls_back_to_participants_when_links_unknown() {
        use mock::MockLeafRunner;
        // Resume case: handle rebuilt from the persisted record only.
        let handle = SubstrateHandle {
            record: SubstrateRecord {
                substrate_id: "vxlan".to_owned(),
                topology_digest: "digest".to_owned(),
                provisioned: true,
                participants: vec!["a".to_owned(), "b".to_owned()],
            },
            overlay_ips: BTreeMap::new(),
            underlay_ips: BTreeMap::new(),
            created_resources: Vec::new(),
        };
        let a = MockLeafRunner::default();
        let b = MockLeafRunner::default();
        let runners = runner_map(&[("a", &a), ("b", &b)]);
        VxlanSubstrateProvider
            .teardown(&handle, &runners)
            .expect("teardown");
        // Three per participant since CN-4: the record cannot say whether a NAT
        // profile was applied, so the router namespace and the site LAN are
        // targeted too and their absence is the idempotent success case.
        // Plus the egress-pin revert and the substrate-transit tail
        // (attestation removal + the two residue probes) per participant.
        let expected_td_len = 4 + substrate_teardown_head().len() + substrate_teardown_tail().len();
        assert_eq!(a.recorded().len(), expected_td_len);
        assert_eq!(b.recorded().len(), expected_td_len);
    }

    #[test]
    fn vxlan_teardown_tolerates_already_deleted_but_fails_on_real_errors() {
        use mock::MockLeafRunner;
        let handle = SubstrateHandle {
            record: SubstrateRecord {
                substrate_id: "vxlan".to_owned(),
                topology_digest: "digest".to_owned(),
                provisioned: true,
                participants: vec!["a".to_owned(), "b".to_owned()],
            },
            overlay_ips: BTreeMap::new(),
            underlay_ips: BTreeMap::new(),
            created_resources: Vec::new(),
        };
        // Calls 0/1/2 are the attestation removal + limit reset + daemon
        // restart; 3..=5 are the three link/netns deletions.
        let gone = MockLeafRunner {
            fail_on: vec![3, 4, 5],
            failure_stderr: "Cannot find device \"rustynet-vx0\"".to_owned(),
            ..MockLeafRunner::default()
        };
        let ok = MockLeafRunner::default();
        let runners = runner_map(&[("a", &gone), ("b", &ok)]);
        VxlanSubstrateProvider
            .teardown(&handle, &runners)
            .expect("already-deleted must be idempotent success");

        let broken = MockLeafRunner {
            fail_on: vec![3],
            failure_stderr: "RTNETLINK answers: Operation not permitted".to_owned(),
            ..MockLeafRunner::default()
        };
        let ok2 = MockLeafRunner::default();
        let runners = runner_map(&[("a", &broken), ("b", &ok2)]);
        let err = VxlanSubstrateProvider
            .teardown(&handle, &runners)
            .expect_err("real deletion failure must fail the teardown");
        assert!(err.contains("possible residue"), "{err}");
        // The OTHER node's removals were still attempted (never stop early),
        // plus its egress-pin revert and substrate-transit tail.
        assert_eq!(
            ok2.recorded().len(),
            4 + substrate_teardown_head().len() + substrate_teardown_tail().len()
        );
    }

    /// A handle rebuilt from the persisted record for participants `a`, `b`.
    fn resume_handle_ab() -> SubstrateHandle {
        SubstrateHandle {
            record: SubstrateRecord {
                substrate_id: "vxlan".to_owned(),
                topology_digest: "digest".to_owned(),
                provisioned: true,
                participants: vec!["a".to_owned(), "b".to_owned()],
            },
            overlay_ips: BTreeMap::new(),
            underlay_ips: BTreeMap::new(),
            created_resources: Vec::new(),
        }
    }

    /// Index of the first recorded call whose joined argv satisfies `pred`.
    fn position_of(calls: &[String], pred: impl Fn(&str) -> bool) -> Option<usize> {
        calls.iter().position(|call| pred(call))
    }

    /// Daemon review finding 16 (security-mandatory): per participant, the
    /// attestation removal and the daemon restart (which rebuilds the boot
    /// table without the transit rule) MUST both precede the first link or
    /// netns deletion, and the residue probes MUST follow the last one.
    /// Deleting the overlay first would leave the boot-table allowance armed
    /// with no overlay behind it.
    fn assert_teardown_order(calls: &[String], who: &str) {
        let remove = position_of(calls, |call| {
            call.contains("vm-lab-remove-substrate-transit")
        })
        .unwrap_or_else(|| panic!("{who}: no attestation removal in {calls:?}"));
        let restart = position_of(calls, |call| call == "sudo -n systemctl restart rustynetd")
            .unwrap_or_else(|| panic!("{who}: no daemon restart in {calls:?}"));
        let first_delete = position_of(calls, |call| {
            call.starts_with("sudo -n ip link del") || call.starts_with("sudo -n ip netns del")
        })
        .unwrap_or_else(|| panic!("{who}: no link deletion in {calls:?}"));
        let last_delete = calls
            .iter()
            .rposition(|call| {
                call.starts_with("sudo -n ip link del") || call.starts_with("sudo -n ip netns del")
            })
            .unwrap_or_else(|| panic!("{who}: no link deletion in {calls:?}"));
        let nft = position_of(calls, |call| call == "sudo -n nft list ruleset")
            .unwrap_or_else(|| panic!("{who}: no nft residue probe in {calls:?}"));
        let attest_probe = position_of(calls, |call| call.starts_with("sudo -n test ! -e"))
            .unwrap_or_else(|| panic!("{who}: no attestation residue probe in {calls:?}"));
        assert!(
            remove < restart,
            "{who}: the attestation must be removed BEFORE the daemon restart: {calls:?}"
        );
        assert!(
            restart < first_delete,
            "{who}: the daemon must be restarted BEFORE any link is deleted: {calls:?}"
        );
        assert!(
            last_delete < nft && last_delete < attest_probe,
            "{who}: the residue assertion must run AFTER the last link deletion: {calls:?}"
        );
    }

    #[test]
    fn teardown_runs_attestation_removal_and_daemon_restart_before_link_deletion() {
        use mock::MockLeafRunner;
        // Resume shape (record-derived targets), two participants.
        let a = MockLeafRunner::default();
        let b = MockLeafRunner::default();
        let runners = runner_map(&[("a", &a), ("b", &b)]);
        VxlanSubstrateProvider
            .teardown(&resume_handle_ab(), &runners)
            .expect("teardown");
        assert_teardown_order(&joined(&a), "a (resume)");
        assert_teardown_order(&joined(&b), "b (resume)");

        // Explicit created-resources shape, interleaved across participants
        // (a NAT'd site: netns + site LAN on `a`).
        let mut handle = resume_handle_ab();
        handle.created_resources = vec![
            CreatedResource::link("a", VXLAN_LINK_NAME),
            CreatedResource::link("b", VXLAN_LINK_NAME),
            CreatedResource::netns("a", VXLAN_ROUTER_NS),
            CreatedResource::link("a", VXLAN_SITE_LAN_IF),
        ];
        let a2 = MockLeafRunner::default();
        let b2 = MockLeafRunner::default();
        let runners = runner_map(&[("a", &a2), ("b", &b2)]);
        VxlanSubstrateProvider
            .teardown(&handle, &runners)
            .expect("teardown");
        assert_teardown_order(&joined(&a2), "a (created)");
        assert_teardown_order(&joined(&b2), "b (created)");
    }

    #[test]
    fn a_transient_attestation_removal_failure_is_retried_once() {
        use mock::MockLeafRunner;
        let a = MockLeafRunner {
            fail_on: vec![0],
            failure_stderr: "transient".to_owned(),
            ..MockLeafRunner::default()
        };
        let b = MockLeafRunner::default();
        let runners = runner_map(&[("a", &a), ("b", &b)]);
        VxlanSubstrateProvider
            .teardown(&resume_handle_ab(), &runners)
            .expect("a retry that succeeds is a clean teardown");
        let calls = joined(&a);
        assert_eq!(
            calls
                .iter()
                .filter(|call| call.contains("vm-lab-remove-substrate-transit"))
                .count(),
            2,
            "{calls:?}"
        );
        assert_teardown_order(&calls, "a (retry)");
    }

    /// Decision (fail closed, but never leave a half-up overlay): when the
    /// attestation cannot be removed even after the retry, the restart and
    /// the link deletions are STILL attempted, and the failure is reported as
    /// residue (the residue assertion also still runs and sees the file).
    #[test]
    fn a_persistent_attestation_removal_failure_is_residue_but_teardown_continues() {
        use mock::MockLeafRunner;
        let a = MockLeafRunner {
            fail_on: vec![0, 1],
            failure_stderr: "Permission denied".to_owned(),
            ..MockLeafRunner::default()
        };
        let b = MockLeafRunner::default();
        let runners = runner_map(&[("a", &a), ("b", &b)]);
        let err = VxlanSubstrateProvider
            .teardown(&resume_handle_ab(), &runners)
            .expect_err("a surviving attestation is residue");
        assert!(err.contains("possible residue"), "{err}");
        assert!(err.contains("attestation removal failed twice"), "{err}");
        let calls = joined(&a);
        assert_teardown_order(&calls, "a (removal failed)");
        // The OTHER participant is untouched by a's failure.
        assert_teardown_order(&joined(&b), "b");
    }

    #[test]
    fn a_failed_daemon_restart_is_residue_but_links_are_still_deleted() {
        use mock::MockLeafRunner;
        // Call 0 = attestation removal, 1 = limit reset, 2 = restart, and on
        // a retrying teardown the second attempt is 3 = reset, 4 = restart.
        let a = MockLeafRunner {
            fail_on: vec![2, 4],
            failure_stderr: "Job for rustynetd.service failed".to_owned(),
            ..MockLeafRunner::default()
        };
        let b = MockLeafRunner::default();
        let runners = runner_map(&[("a", &a), ("b", &b)]);
        let err = VxlanSubstrateProvider
            .teardown(&resume_handle_ab(), &runners)
            .expect_err("a failed restart leaves the boot table unverified");
        assert!(err.contains("possible residue"), "{err}");
        assert!(err.contains("boot table not rebuilt"), "{err}");
        let calls = joined(&a);
        assert_teardown_order(&calls, "a (restart failed)");
        // A transport failure of the restart is the same residue channel.
        let c = MockLeafRunner {
            transport_error_on: vec![2, 4],
            ..MockLeafRunner::default()
        };
        let d = MockLeafRunner::default();
        let runners = runner_map(&[("a", &c), ("b", &d)]);
        let err = VxlanSubstrateProvider
            .teardown(&resume_handle_ab(), &runners)
            .expect_err("a restart that cannot run is residue");
        assert!(err.contains("rustynetd restart"), "{err}");
        assert_teardown_order(&joined(&c), "a (restart transport)");
    }

    /// A guest that never got a `rustynetd` unit (setup failed before the
    /// install stage) has no ExecStartPre to rebuild; that is not residue.
    #[test]
    fn a_guest_without_a_daemon_unit_is_not_residue_for_the_restart_step() {
        use mock::MockLeafRunner;
        let a = MockLeafRunner {
            fail_on: vec![2],
            failure_stderr:
                "Failed to restart rustynetd.service: Unit rustynetd.service not found.".to_owned(),
            ..MockLeafRunner::default()
        };
        let b = MockLeafRunner::default();
        let runners = runner_map(&[("a", &a), ("b", &b)]);
        VxlanSubstrateProvider
            .teardown(&resume_handle_ab(), &runners)
            .expect("an absent unit is not residue");
        assert_teardown_order(&joined(&a), "a (no unit)");
    }

    /// u41-r2 teardown fix: a guest that crash-looped earlier in the run arms
    /// systemd's start-rate limit, so the teardown's restart must be preceded
    /// by `systemctl reset-failed` on EVERY attempt, and a first restart
    /// refused for rate limiting must be retried once — not reported as
    /// residue.
    #[test]
    fn daemon_restart_resets_failed_state_before_restart_and_retries_once() {
        use mock::MockLeafRunner;
        let a = MockLeafRunner {
            // Call 2 is the first restart; its rate-limit failure must not
            // become residue.
            fail_on: vec![2],
            failure_stderr: "Start request repeated too quickly.".to_owned(),
            ..MockLeafRunner::default()
        };
        let b = MockLeafRunner::default();
        let runners = runner_map(&[("a", &a), ("b", &b)]);
        VxlanSubstrateProvider
            .teardown(&resume_handle_ab(), &runners)
            .expect("a rate-limited first restart is retried, not residue");
        let calls = joined(&a);
        let count = |needle: &str| calls.iter().filter(|call| call.contains(needle)).count();
        assert_eq!(count("systemctl reset-failed rustynetd"), 2, "{calls:?}");
        assert_eq!(count("systemctl restart rustynetd"), 2, "{calls:?}");
        let remove = position_of(&calls, |call| {
            call.contains("vm-lab-remove-substrate-transit")
        })
        .expect("removal");
        let reset1 = position_of(&calls, |call| call.contains("reset-failed")).expect("reset1");
        let restart1 = position_of(&calls, |call| call == "sudo -n systemctl restart rustynetd")
            .expect("restart1");
        let reset2 = calls
            .iter()
            .rposition(|call| call.contains("reset-failed"))
            .expect("reset2");
        let restart2 = calls
            .iter()
            .rposition(|call| call == "sudo -n systemctl restart rustynetd")
            .expect("restart2");
        let first_delete = position_of(&calls, |call| {
            call.starts_with("sudo -n ip link del") || call.starts_with("sudo -n ip netns del")
        })
        .expect("first delete");
        assert!(remove < reset1 && reset1 < restart1, "{calls:?}");
        assert!(restart1 < reset2 && reset2 < restart2, "{calls:?}");
        assert!(restart2 < first_delete, "{calls:?}");
        assert_teardown_order(&calls, "a (rate-limited restart)");
    }

    /// Both restart attempts failing stays residue (fail closed), and the
    /// link deletions still happen.
    #[test]
    fn a_daemon_restart_that_fails_twice_is_still_residue() {
        use mock::MockLeafRunner;
        let a = MockLeafRunner {
            fail_on: vec![2, 4],
            failure_stderr: "Start request repeated too quickly.".to_owned(),
            ..MockLeafRunner::default()
        };
        let b = MockLeafRunner::default();
        let runners = runner_map(&[("a", &a), ("b", &b)]);
        let err = VxlanSubstrateProvider
            .teardown(&resume_handle_ab(), &runners)
            .expect_err("an unrecoverable restart is residue");
        assert!(err.contains("possible residue"), "{err}");
        assert!(err.contains("boot table not rebuilt"), "{err}");
        let calls = joined(&a);
        assert_eq!(
            calls
                .iter()
                .filter(|call| {
                    call.starts_with("sudo -n ip link del")
                        || call.starts_with("sudo -n ip netns del")
                })
                .count(),
            3,
            "deletions still run: {calls:?}"
        );
    }

    /// A failing `reset-failed` must not block the boot-table rebuild: the
    /// restart is the gate, the reset is best-effort.
    #[test]
    fn reset_failed_failure_does_not_block_the_boot_table_rebuild() {
        use mock::MockLeafRunner;
        let a = MockLeafRunner {
            // Reset fails on BOTH attempts and the first restart is
            // rate-limited; the retry must still reach a clean teardown.
            fail_on: vec![1, 2, 3],
            failure_stderr: "Failed to query unit: Unit rustynetd.service not loaded.".to_owned(),
            ..MockLeafRunner::default()
        };
        let b = MockLeafRunner::default();
        let runners = runner_map(&[("a", &a), ("b", &b)]);
        VxlanSubstrateProvider
            .teardown(&resume_handle_ab(), &runners)
            .expect("reset-failed failures are not residue");
        let calls = joined(&a);
        assert_eq!(
            calls
                .iter()
                .filter(|call| call.contains("reset-failed"))
                .count(),
            2,
            "{calls:?}"
        );
        assert_teardown_order(&calls, "a (reset failed)");
    }

    /// u41-r2 fix 1 + review finding 3: after the reboot-recovery stage
    /// reboots guests in a vxlan run, the persisted substrate is re-created
    /// for the REBOOTED ALIASES ONLY (no overlay bounce under live nodes),
    /// fdb entries still name every peer, and the fresh created resources
    /// are MERGED into the live handle so teardown removes everything.
    #[test]
    fn reprovision_after_guest_reboot_touches_only_rebooted_nodes_and_merges_resources() {
        let mut ctx = empty_ctx();
        let topo = two_lan_topology();
        let plan = plan_overlay(&topo)
            .expect("plan")
            .expect("two network groups need an overlay");
        let digest = topology_digest("vxlan", &topo, Some(&plan));
        ctx.substrate_record = Some(SubstrateRecord {
            substrate_id: "vxlan".to_owned(),
            topology_digest: digest.clone(),
            provisioned: true,
            participants: topo.nodes.keys().cloned().collect(),
        });
        ctx.substrate = Some(SubstrateHandle {
            record: ctx.substrate_record.clone().expect("record"),
            overlay_ips: BTreeMap::new(),
            underlay_ips: BTreeMap::new(),
            created_resources: vec![CreatedResource::netns("lenovo-1", VXLAN_ROUTER_NS)],
        });
        let lenovo = substrate_ready_runner();
        let utm1 = substrate_ready_runner();
        let utm2 = substrate_ready_runner();
        let runners = runner_map(&[("lenovo-1", &lenovo), ("utm-1", &utm1), ("utm-2", &utm2)]);
        reprovision_substrate_after_guest_reboot(&mut ctx, &topo, &runners, &["utm-1"])
            .expect("re-provisioning the rebooted node restores the overlay");
        assert!(
            lenovo.recorded().is_empty(),
            "lenovo-1 did not reboot: {:?}",
            lenovo.recorded()
        );
        assert!(
            utm2.recorded().is_empty(),
            "utm-2 did not reboot: {:?}",
            utm2.recorded()
        );
        let calls = joined(&utm1);
        assert!(
            calls
                .iter()
                .any(|call| call.contains("ip link add") && call.contains(VXLAN_LINK_NAME)),
            "no vxlan link re-created on the rebooted node: {calls:?}"
        );
        // fdb for EVERY peer, so the rebooted node rejoins the whole mesh.
        assert!(
            calls
                .iter()
                .any(|call| call.contains("fdb") && call.contains("192.168.0.30")),
            "no fdb entry for lenovo-1: {calls:?}"
        );
        assert!(
            calls
                .iter()
                .any(|call| call.contains("fdb") && call.contains("192.168.64.11")),
            "no fdb entry for utm-2: {calls:?}"
        );
        assert!(
            calls
                .iter()
                .any(|call| call.contains("vm-lab-write-substrate-transit")),
            "no attestation rewritten: {calls:?}"
        );
        let handle = ctx.substrate.expect("the live handle is refreshed");
        assert!(handle.overlay_ips.contains_key("lenovo-1"));
        assert!(
            handle
                .created_resources
                .contains(&CreatedResource::netns("lenovo-1", VXLAN_ROUTER_NS)),
            "merge must keep pre-reboot resources: {:?}",
            handle.created_resources
        );
        assert!(
            handle
                .created_resources
                .contains(&CreatedResource::link("utm-1", VXLAN_LINK_NAME)),
            "merge must add the re-created resources: {:?}",
            handle.created_resources
        );
        let record = ctx.substrate_record.expect("the record is refreshed");
        assert!(record.provisioned);
        assert_eq!(record.topology_digest, digest);
    }

    /// A rebooted alias that is not a topology participant is a hard error,
    /// never an index panic or a silent skip.
    #[test]
    fn reprovision_after_guest_reboot_refuses_a_rebooted_alias_outside_the_topology() {
        use mock::MockLeafRunner;
        let mut ctx = empty_ctx();
        let topo = two_lan_topology();
        let plan = plan_overlay(&topo)
            .expect("plan")
            .expect("two network groups need an overlay");
        ctx.substrate_record = Some(SubstrateRecord {
            substrate_id: "vxlan".to_owned(),
            topology_digest: topology_digest("vxlan", &topo, Some(&plan)),
            provisioned: true,
            participants: topo.nodes.keys().cloned().collect(),
        });
        let ready = MockLeafRunner::default();
        let runners = runner_map(&[("lenovo-1", &ready)]);
        let err = reprovision_substrate_after_guest_reboot(
            &mut ctx,
            &topo,
            &runners,
            &["ghost-not-in-topology"],
        )
        .expect_err("an unknown rebooted alias must fail closed");
        assert!(err.contains("not a participant"), "{err}");
        assert!(ready.recorded().is_empty());
        assert!(ctx.substrate.is_none());
    }

    /// A run without a provisioned substrate (no record, or a recorded no-op)
    /// is untouched by the re-provision: no leaf command may run.
    #[test]
    fn reprovision_after_guest_reboot_skips_when_not_provisioned() {
        use mock::MockLeafRunner;
        let topo = two_lan_topology();
        let mut ctx = empty_ctx();
        let a = MockLeafRunner::default();
        let b = MockLeafRunner::default();
        let runners = runner_map(&[("lenovo-1", &a), ("utm-1", &b)]);
        reprovision_substrate_after_guest_reboot(&mut ctx, &topo, &runners, &[])
            .expect("no substrate, nothing to re-provision");
        assert!(a.recorded().is_empty());
        assert!(ctx.substrate.is_none());
        let mut ctx = empty_ctx();
        ctx.substrate_record = Some(vxlan_record(false));
        let c = MockLeafRunner::default();
        let runners = runner_map(&[("lenovo-1", &c)]);
        reprovision_substrate_after_guest_reboot(&mut ctx, &topo, &runners, &[])
            .expect("a recorded no-op stays a no-op");
        assert!(c.recorded().is_empty());
        // And the stage-level glue skips before building any runner.
        let mut ctx = empty_ctx();
        ctx.substrate_record = Some(vxlan_record(false));
        reprovision_and_verify_after_reboot(&mut ctx, &["lenovo-1"])
            .expect("the glue passes without a substrate");
    }

    /// A persisted substrate this build has no provider for is a hard
    /// failure, never a silent skip.
    #[test]
    fn reprovision_after_guest_reboot_fails_closed_on_unknown_substrate() {
        use mock::MockLeafRunner;
        let mut ctx = empty_ctx();
        ctx.substrate_record = Some(SubstrateRecord {
            substrate_id: "mystery".to_owned(),
            topology_digest: "digest".to_owned(),
            provisioned: true,
            participants: vec!["a".to_owned()],
        });
        let a = MockLeafRunner::default();
        let runners = runner_map(&[("a", &a)]);
        let err = reprovision_substrate_after_guest_reboot(
            &mut ctx,
            &topology(&[("a", "192.168.64.10"), ("b", "192.168.0.30")]),
            &runners,
            &["a"],
        )
        .expect_err("unknown substrate must fail closed");
        assert!(err.contains("no re-provision provider"), "{err}");
        assert!(err.contains("mystery"), "{err}");
        assert!(a.recorded().is_empty());
    }

    /// A topology that no longer digests to the persisted record (the
    /// inventory changed under the overlay) refuses to re-provision stale
    /// addressing.
    #[test]
    fn reprovision_after_guest_reboot_refuses_a_topology_mismatch() {
        use mock::MockLeafRunner;
        let mut ctx = empty_ctx();
        let topo = two_lan_topology();
        ctx.substrate_record = Some(SubstrateRecord {
            substrate_id: "vxlan".to_owned(),
            topology_digest: "stale".to_owned(),
            provisioned: true,
            participants: topo.nodes.keys().cloned().collect(),
        });
        let a = MockLeafRunner::default();
        let b = MockLeafRunner::default();
        let c = MockLeafRunner::default();
        let runners = runner_map(&[("lenovo-1", &a), ("utm-1", &b), ("utm-2", &c)]);
        let err = reprovision_substrate_after_guest_reboot(&mut ctx, &topo, &runners, &["utm-1"])
            .expect_err("a changed inventory must fail closed");
        assert!(err.contains("substrate topology mismatch"), "{err}");
        assert!(
            a.recorded().is_empty(),
            "no overlay command may run: {:?}",
            a.recorded()
        );
    }

    // ── u41-r3 (b115): post-reboot daemon recovery + mesh verification ──

    fn now_unix() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs()
    }

    fn no_sleep(_: std::time::Duration) {}

    /// A mock whose `is-active` probes answer with the given states in
    /// order, the last one repeating.
    fn is_active_seq(states: &[&str]) -> mock::MockLeafRunner {
        mock::MockLeafRunner {
            stdout_seq_by_match: vec![(
                "is-active".to_owned(),
                states.iter().map(|state| format!("{state}\n")).collect(),
            )],
            ..mock::MockLeafRunner::default()
        }
    }

    /// A guest mock that survives re-provision (route-get derivation),
    /// answers `is-active` with the given sequence, and reports a wireguard
    /// handshake `handshake_age_secs` old (negative = the guest clock is
    /// slightly ahead of ours).
    fn recovering_runner(states: &[&str], handshake_age_secs: i64) -> mock::MockLeafRunner {
        let mut runner = is_active_seq(states);
        runner
            .stdout_by_match
            .push(("route get".to_owned(), route_answer_stdout()));
        let timestamp = (now_unix() as i64 - handshake_age_secs) as u64;
        runner.stdout_by_match.push((
            "latest-handshakes".to_owned(),
            format!("rustynet0\tpeer-public-key\t{timestamp}\n"),
        ));
        runner
    }

    /// Review finding 1: a latched unit recovers — reset-failed runs first,
    /// then the restart (whose ExecStartPre rebuilds the boot table), then a
    /// bounded poll that needs `active` twice in a row, then the mesh check.
    #[test]
    fn daemon_recovery_resets_the_latch_restarts_then_requires_stable_active() {
        let a = recovering_runner(&["activating", "active", "active"], 10);
        let runners = runner_map(&[("a", &a)]);
        recover_and_verify_rebooted_guests(&runners, &["a"], now_unix(), &no_sleep)
            .expect("a latched unit that re-converges must pass");
        let calls = joined(&a);
        assert_eq!(
            calls
                .iter()
                .filter(|call| call.contains("reset-failed"))
                .count(),
            1,
            "{calls:?}"
        );
        assert_eq!(
            calls
                .iter()
                .filter(|call| call.contains("systemctl restart rustynetd"))
                .count(),
            1,
            "{calls:?}"
        );
        let reset = position_of(&calls, |call| call.contains("reset-failed")).expect("reset");
        let restart = position_of(&calls, |call| call.contains("systemctl restart rustynetd"))
            .expect("restart");
        let first_poll = position_of(&calls, |call| call.contains("is-active")).expect("poll");
        assert!(
            reset < restart && restart < first_poll,
            "reset-failed < restart < poll required: {calls:?}"
        );
        assert_eq!(
            calls
                .iter()
                .filter(|call| call.contains("is-active"))
                .count(),
            3,
            "two consecutive actives must stop the poll: {calls:?}"
        );
        assert!(
            calls.iter().any(|call| call.contains("latest-handshakes")),
            "mesh re-convergence is checked too: {calls:?}"
        );
    }

    /// Review finding 1: a daemon that never reaches `active` fails after
    /// exactly the bounded number of polls, naming the last state.
    #[test]
    fn daemon_recovery_poll_is_bounded_and_names_the_last_state() {
        let a = recovering_runner(&["inactive"], 10);
        let runners = runner_map(&[("a", &a)]);
        let err = recover_and_verify_rebooted_guests(&runners, &["a"], now_unix(), &no_sleep)
            .expect_err("a daemon that never reaches active must fail");
        assert!(err.contains("did not reach a stable active state"), "{err}");
        assert!(
            err.contains("\"inactive\""),
            "the last state must be named: {err}"
        );
        let calls = joined(&a);
        assert_eq!(
            calls
                .iter()
                .filter(|call| call.contains("is-active"))
                .count(),
            DAEMON_ACTIVE_POLL_ATTEMPTS,
            "the poll must be bounded by the constant"
        );
        assert!(
            !calls.iter().any(|call| call.contains("latest-handshakes")),
            "no mesh check for a guest whose daemon never came back: {calls:?}"
        );
    }

    /// The poll is bounded by `attempts`, sleeps only BETWEEN probes, and a
    /// single `active` read never decides recovery.
    #[test]
    fn daemon_poll_requires_two_consecutive_active_probes_within_its_bound() {
        let sleeps = std::cell::Cell::new(0usize);
        let count_sleep = |_: std::time::Duration| sleeps.set(sleeps.get() + 1);
        let flapping = is_active_seq(&["active", "inactive"]);
        poll_daemon_active(&flapping, "a", 5, &count_sleep)
            .expect_err("a single active probe must not decide recovery");
        assert_eq!(flapping.recorded().len(), 5, "bounded by attempts");
        assert_eq!(sleeps.get(), 4, "sleep between polls, not before the first");
        let settles = is_active_seq(&["inactive", "active", "active"]);
        poll_daemon_active(&settles, "a", 5, &count_sleep)
            .expect("two consecutive actives pass early");
        assert_eq!(settles.recorded().len(), 3);
        assert_eq!(sleeps.get(), 6, "2 + 4 sleeps across both polls");
    }

    /// The documented budget: 30 polls, 2 s apart (≈58 s of sleeps plus
    /// probe time — the review's "up to ~60 s").
    #[test]
    fn daemon_poll_bound_is_the_documented_sixty_second_budget() {
        assert_eq!(DAEMON_ACTIVE_POLL_ATTEMPTS, 30);
        assert_eq!(
            DAEMON_ACTIVE_POLL_INTERVAL,
            std::time::Duration::from_secs(2)
        );
        assert_eq!(
            DAEMON_ACTIVE_POLL_INTERVAL * (DAEMON_ACTIVE_POLL_ATTEMPTS as u32 - 1),
            std::time::Duration::from_secs(58),
        );
    }

    /// Review finding 2: the mesh gate. Fresh handshake passes (a guest
    /// clock a few seconds ahead counts as fresh too); stale, absent,
    /// failing and unrunnable probes all fail closed.
    #[test]
    fn the_handshake_gate_requires_a_fresh_rekey() {
        let now = now_unix();
        let handshake = |age: i64| mock::MockLeafRunner {
            stdout_by_match: vec![(
                "latest-handshakes".to_owned(),
                format!(
                    "rustynet0\tpeer-public-key\t{}\n",
                    (now as i64 - age) as u64
                ),
            )],
            ..mock::MockLeafRunner::default()
        };
        assert_fresh_wg_handshake(&handshake(10), "a", now).expect("a 10s-old handshake is fresh");
        assert_fresh_wg_handshake(&handshake(-5), "a", now)
            .expect("a slightly future stamp (guest clock skew) is fresh");
        let err = assert_fresh_wg_handshake(&handshake(10_000), "a", now)
            .expect_err("a stale handshake fails");
        assert!(err.contains("did not re-key"), "{err}");
        let err = assert_fresh_wg_handshake(&mock::MockLeafRunner::default(), "a", now)
            .expect_err("no handshake at all fails");
        assert!(err.contains("no handshakes"), "{err}");
        let broken = mock::MockLeafRunner {
            transport_error_on: vec![0],
            ..mock::MockLeafRunner::default()
        };
        let err = assert_fresh_wg_handshake(&broken, "a", now)
            .expect_err("an unrunnable probe fails closed");
        assert!(err.contains("wg handshake probe"), "{err}");
        let failing = mock::MockLeafRunner {
            fail_on: vec![0],
            failure_stderr: "operation not permitted".to_owned(),
            ..mock::MockLeafRunner::default()
        };
        let err = assert_fresh_wg_handshake(&failing, "a", now)
            .expect_err("a failing probe fails closed");
        assert!(err.contains("latest-handshakes failed"), "{err}");
    }

    fn userspace_runner(netcheck: &str) -> mock::MockLeafRunner {
        mock::MockLeafRunner {
            stdout_by_match: vec![("netcheck".to_owned(), netcheck.to_owned())],
            ..mock::MockLeafRunner::default()
        }
    }

    fn netcheck_with(state: &str, handshake: &str) -> String {
        format!(
            "netcheck: path_mode=direct_active path_live_proven=true \
             path_latest_live_handshake_unix={handshake} \
             transport_socket_identity_state={state} traversal_error=none"
        )
    }

    /// katana-xnet-66: userspace-shared keeps WireGuard in the daemon, kernel
    /// `wg` is empty, and the daemon's own fresh handshake is the evidence, with
    /// the same freshness bound.
    #[test]
    fn the_handshake_gate_accepts_the_daemons_fresh_handshake_for_userspace_shared() {
        let now = now_unix();
        let ok = |age: u64| {
            userspace_runner(&netcheck_with(
                "authoritative_backend_shared_transport",
                &(now - age).to_string(),
            ))
        };
        assert_fresh_wg_handshake(&ok(10), "a", now).expect("a 10s-old daemon handshake is fresh");
        let err = assert_fresh_wg_handshake(&ok(10_000), "a", now)
            .expect_err("a stale daemon handshake fails");
        assert!(err.contains("did not re-key"), "{err}");
    }

    /// No vacuous pass: every shape of missing, unknown or unusable daemon
    /// evidence fails, and the kernel authority is never overridden.
    #[test]
    fn the_daemon_fallback_never_passes_on_absent_or_ambiguous_evidence() {
        let now = now_unix();
        let fresh = now.to_string();
        let cases = [
            // userspace but no live peer
            netcheck_with("authoritative_backend_shared_transport", "none"),
            // userspace but the field is garbage / negative-looking
            netcheck_with("authoritative_backend_shared_transport", "-5"),
            netcheck_with("authoritative_backend_shared_transport", "12x"),
            netcheck_with("authoritative_backend_shared_transport", ""),
            // kernel backend: kernel wg saw nothing, a daemon stamp is NOT trusted
            netcheck_with("blocked_backend_opaque_socket", &fresh),
            // unknown backend states
            netcheck_with("authoritative_backend_shared_transport_unavailable", &fresh),
            netcheck_with("not_required", &fresh),
            // not a netcheck at all
            String::new(),
            "path_latest_live_handshake_unix=1".to_owned(),
        ];
        for netcheck in cases {
            let err = assert_fresh_wg_handshake(&userspace_runner(&netcheck), "a", now)
                .expect_err(&format!("must fail closed: {netcheck:?}"));
            assert!(err.contains("no handshakes"), "{netcheck:?}: {err}");
        }
        // The daemon probe itself failing or being unrunnable fails closed.
        let failing = mock::MockLeafRunner {
            fail_on: vec![1],
            failure_stderr: "connection refused".to_owned(),
            ..mock::MockLeafRunner::default()
        };
        let err = assert_fresh_wg_handshake(&failing, "a", now).expect_err("netcheck failed");
        assert!(err.contains("daemon netcheck failed"), "{err}");
        let broken = mock::MockLeafRunner {
            transport_error_on: vec![1],
            ..mock::MockLeafRunner::default()
        };
        let err = assert_fresh_wg_handshake(&broken, "a", now).expect_err("netcheck unrunnable");
        assert!(err.contains("daemon netcheck probe"), "{err}");
    }

    /// The kernel path is untouched: a fresh kernel handshake never consults the
    /// daemon, and a STALE kernel handshake is not rescued by a fresh daemon one.
    #[test]
    fn the_kernel_handshake_path_never_consults_the_daemon() {
        let now = now_unix();
        let netcheck = netcheck_with("authoritative_backend_shared_transport", &now.to_string());
        let kernel = |age: u64| mock::MockLeafRunner {
            stdout_by_match: vec![
                (
                    "latest-handshakes".to_owned(),
                    format!("rustynet0\tpeer\t{}\n", now - age),
                ),
                ("netcheck".to_owned(), netcheck.clone()),
            ],
            ..mock::MockLeafRunner::default()
        };
        let fresh = kernel(5);
        assert_fresh_wg_handshake(&fresh, "a", now).expect("fresh kernel handshake");
        assert_eq!(fresh.recorded().len(), 1, "only the kernel probe ran");
        let stale = kernel(10_000);
        assert_fresh_wg_handshake(&stale, "a", now)
            .expect_err("a stale kernel handshake stays a failure");
        assert_eq!(stale.recorded().len(), 1, "the daemon must not rescue it");
    }

    /// Recovery fails closed on a rebooted node with no runner, on a restart
    /// that fails, and on a unit that vanished — and a failed restart never
    /// reaches the poll.
    #[test]
    fn daemon_recovery_fails_closed_on_a_missing_runner_a_failed_restart_or_a_vanished_unit() {
        let good = recovering_runner(&["activating", "active", "active"], 10);
        let runners = runner_map(&[("a", &good)]);
        let err =
            recover_and_verify_rebooted_guests(&runners, &["a", "ghost"], now_unix(), &no_sleep)
                .expect_err("a rebooted node with no runner is a failure, never a skip");
        assert!(err.contains("ghost"), "{err}");

        let restart_fails = mock::MockLeafRunner {
            fail_on: vec![1],
            failure_stderr: "Job for rustynetd.service failed".to_owned(),
            ..recovering_runner(&["active"], 10)
        };
        let runners = runner_map(&[("a", &restart_fails)]);
        let err = recover_and_verify_rebooted_guests(&runners, &["a"], now_unix(), &no_sleep)
            .expect_err("a failed restart is a hard error");
        assert!(err.contains("restart failed after the reboot"), "{err}");
        assert!(
            !joined(&restart_fails)
                .iter()
                .any(|call| call.contains("is-active")),
            "no point polling a daemon that never restarted: {:?}",
            joined(&restart_fails)
        );

        let unit_gone = mock::MockLeafRunner {
            fail_on: vec![1],
            failure_stderr:
                "Failed to restart rustynetd.service: Unit rustynetd.service not found.".to_owned(),
            ..recovering_runner(&["active"], 10)
        };
        let runners = runner_map(&[("a", &unit_gone)]);
        let err = recover_and_verify_rebooted_guests(&runners, &["a"], now_unix(), &no_sleep)
            .expect_err("a vanished unit cannot be verified");
        assert!(err.contains("no rustynetd unit"), "{err}");
    }

    /// The full glue happy path: only rebooted nodes are touched, daemons
    /// are reset+restarted+polled, handshakes checked, and the evidence line
    /// is written LAST with only true claims (review findings 2 + 5).
    #[test]
    fn reboot_glue_recovers_verifies_then_records_honest_evidence() {
        let mut ctx = empty_ctx();
        let topo = two_lan_topology();
        let plan = plan_overlay(&topo)
            .expect("plan")
            .expect("two network groups need an overlay");
        ctx.substrate_record = Some(SubstrateRecord {
            substrate_id: "vxlan".to_owned(),
            topology_digest: topology_digest("vxlan", &topo, Some(&plan)),
            provisioned: true,
            participants: topo.nodes.keys().cloned().collect(),
        });
        let lenovo = substrate_ready_runner();
        let utm1 = recovering_runner(&["activating", "active", "active"], 10);
        let utm2 = recovering_runner(&["activating", "active", "active"], 10);
        let runners = runner_map(&[("lenovo-1", &lenovo), ("utm-1", &utm1), ("utm-2", &utm2)]);
        let evidence = std::cell::RefCell::new(None::<String>);
        let polls_at_evidence = std::cell::Cell::new(0usize);
        let record = |line: &str| -> Result<(), String> {
            polls_at_evidence.set(
                utm1.recorded()
                    .iter()
                    .filter(|call| call.join(" ").contains("is-active"))
                    .count(),
            );
            *evidence.borrow_mut() = Some(line.to_owned());
            Ok(())
        };
        reprovision_and_verify_after_reboot_with(
            &mut ctx,
            &topo,
            &["utm-1", "utm-2"],
            &runners,
            &record,
            &no_sleep,
        )
        .expect("a re-provisioned overlay with recovered daemons passes");
        assert!(
            lenovo.recorded().is_empty(),
            "lenovo-1 did not reboot: {:?}",
            lenovo.recorded()
        );
        for (alias, runner) in [("utm-1", &utm1), ("utm-2", &utm2)] {
            let calls = joined(runner);
            let reset = position_of(&calls, |call| call.contains("reset-failed"))
                .unwrap_or_else(|| panic!("{alias}: no reset-failed: {calls:?}"));
            let restart = position_of(&calls, |call| call.contains("systemctl restart rustynetd"))
                .unwrap_or_else(|| panic!("{alias}: no restart: {calls:?}"));
            let first_poll = position_of(&calls, |call| call.contains("is-active"))
                .unwrap_or_else(|| panic!("{alias}: no poll: {calls:?}"));
            assert!(
                reset < restart && restart < first_poll,
                "{alias}: recovery order wrong: {calls:?}"
            );
            assert!(
                calls.iter().any(|call| call.contains("latest-handshakes")),
                "{alias}: no wg probe: {calls:?}"
            );
        }
        let line = evidence.borrow().clone().expect("evidence recorded");
        assert!(
            line.contains("daemon_active=restarted-and-verified:utm-1,utm-2"),
            "{line}"
        );
        assert!(line.contains("wg_handshake_fresh=verified"), "{line}");
        assert!(line.contains("post_reboot_twohop=not-verified"), "{line}");
        assert!(
            line.contains("post_reboot_dns_refresh=not-verified"),
            "{line}"
        );
        assert!(
            line.contains("overlay_nodes=lenovo-1,utm-1,utm-2"),
            "{line}"
        );
        assert!(
            polls_at_evidence.get() >= 3,
            "evidence must be written AFTER the daemon checks, not before"
        );
    }

    /// Review mutant m14: if the glue dropped the daemon check entirely, a
    /// daemon that never recovers must still fail the stage — and no
    /// evidence line may be recorded.
    #[test]
    fn reboot_glue_fails_when_a_rebooted_daemon_never_recovers() {
        let mut ctx = empty_ctx();
        let topo = two_lan_topology();
        let plan = plan_overlay(&topo)
            .expect("plan")
            .expect("two network groups need an overlay");
        ctx.substrate_record = Some(SubstrateRecord {
            substrate_id: "vxlan".to_owned(),
            topology_digest: topology_digest("vxlan", &topo, Some(&plan)),
            provisioned: true,
            participants: topo.nodes.keys().cloned().collect(),
        });
        let lenovo = substrate_ready_runner();
        let utm1 = recovering_runner(&["inactive"], 10);
        let utm2 = recovering_runner(&["activating", "active", "active"], 10);
        let runners = runner_map(&[("lenovo-1", &lenovo), ("utm-1", &utm1), ("utm-2", &utm2)]);
        let evidence_calls = std::cell::Cell::new(0usize);
        let record = |_: &str| -> Result<(), String> {
            evidence_calls.set(evidence_calls.get() + 1);
            Ok(())
        };
        let err = reprovision_and_verify_after_reboot_with(
            &mut ctx,
            &topo,
            &["utm-1", "utm-2"],
            &runners,
            &record,
            &no_sleep,
        )
        .expect_err("a daemon that never recovers must fail the stage");
        assert!(err.contains("did not reach a stable active state"), "{err}");
        assert!(err.contains("utm-1"), "{err}");
        let calls = joined(&utm1);
        assert!(
            calls.iter().any(|call| call.contains("reset-failed")),
            "the latch reset must be attempted: {calls:?}"
        );
        assert!(
            calls
                .iter()
                .any(|call| call.contains("systemctl restart rustynetd")),
            "the restart must be attempted: {calls:?}"
        );
        assert_eq!(
            calls
                .iter()
                .filter(|call| call.contains("is-active"))
                .count(),
            DAEMON_ACTIVE_POLL_ATTEMPTS,
            "bounded poll: {calls:?}"
        );
        assert_eq!(
            evidence_calls.get(),
            0,
            "no evidence line when verification failed"
        );
    }

    /// Review mutant m13: a failing evidence write must fail the glue, and
    /// it must be attempted only after every check passed.
    #[test]
    fn reboot_glue_fails_when_the_evidence_line_cannot_be_written() {
        let mut ctx = empty_ctx();
        let topo = two_lan_topology();
        let plan = plan_overlay(&topo)
            .expect("plan")
            .expect("two network groups need an overlay");
        ctx.substrate_record = Some(SubstrateRecord {
            substrate_id: "vxlan".to_owned(),
            topology_digest: topology_digest("vxlan", &topo, Some(&plan)),
            provisioned: true,
            participants: topo.nodes.keys().cloned().collect(),
        });
        let lenovo = substrate_ready_runner();
        let utm1 = recovering_runner(&["activating", "active", "active"], 10);
        let utm2 = recovering_runner(&["activating", "active", "active"], 10);
        let runners = runner_map(&[("lenovo-1", &lenovo), ("utm-1", &utm1), ("utm-2", &utm2)]);
        let record = |_: &str| -> Result<(), String> { Err("stage log disk full".to_owned()) };
        let err = reprovision_and_verify_after_reboot_with(
            &mut ctx,
            &topo,
            &["utm-1", "utm-2"],
            &runners,
            &record,
            &no_sleep,
        )
        .expect_err("a failing evidence write must fail the stage");
        assert!(err.contains("stage log disk full"), "{err}");
        assert!(
            !lenovo.recorded().is_empty() || !utm1.recorded().is_empty(),
            "the evidence write is attempted after the checks ran"
        );
    }

    /// Review mutants m12 + m16: a setup failure in the re-provision fails
    /// the glue AND stores the merged partial handle/record for teardown;
    /// non-rebooted nodes stay untouched and no evidence is written.
    #[test]
    fn reboot_glue_setup_failure_fails_and_records_merged_partial_state() {
        let mut ctx = empty_ctx();
        let topo = two_lan_topology();
        let plan = plan_overlay(&topo)
            .expect("plan")
            .expect("two network groups need an overlay");
        ctx.substrate_record = Some(SubstrateRecord {
            substrate_id: "vxlan".to_owned(),
            topology_digest: topology_digest("vxlan", &topo, Some(&plan)),
            provisioned: true,
            participants: topo.nodes.keys().cloned().collect(),
        });
        ctx.substrate = Some(SubstrateHandle {
            record: ctx.substrate_record.clone().expect("record"),
            overlay_ips: BTreeMap::new(),
            underlay_ips: BTreeMap::new(),
            created_resources: vec![CreatedResource::netns("lenovo-1", VXLAN_ROUTER_NS)],
        });
        let lenovo = mock::MockLeafRunner::default();
        let utm1 = mock::MockLeafRunner {
            // Call 0 pre-delete, call 1 link add: fail the link add.
            fail_on: vec![1],
            failure_stderr: "RTNETLINK answers: Operation not permitted".to_owned(),
            ..substrate_ready_runner()
        };
        let utm2 = substrate_ready_runner();
        let runners = runner_map(&[("lenovo-1", &lenovo), ("utm-1", &utm1), ("utm-2", &utm2)]);
        let evidence_calls = std::cell::Cell::new(0usize);
        let record = |_: &str| -> Result<(), String> {
            evidence_calls.set(evidence_calls.get() + 1);
            Ok(())
        };
        let err = reprovision_and_verify_after_reboot_with(
            &mut ctx,
            &topo,
            &["utm-1"],
            &runners,
            &record,
            &no_sleep,
        )
        .expect_err("a failed re-provision must fail the stage");
        assert!(err.contains("partial state recorded"), "{err}");
        assert!(err.contains("utm-1"), "{err}");
        assert!(
            lenovo.recorded().is_empty(),
            "non-rebooted nodes untouched: {:?}",
            lenovo.recorded()
        );
        assert!(utm2.recorded().is_empty());
        let handle = ctx
            .substrate
            .expect("partial state must be stored for teardown");
        assert!(
            handle.overlay_ips.contains_key("utm-1"),
            "the stored handle must be the re-provision partial: {:?}",
            handle.overlay_ips.keys().collect::<Vec<_>>()
        );
        assert!(
            handle
                .created_resources
                .contains(&CreatedResource::netns("lenovo-1", VXLAN_ROUTER_NS)),
            "previous resources must survive the merge: {:?}",
            handle.created_resources
        );
        assert!(ctx.substrate_record.expect("record").provisioned);
        assert_eq!(
            evidence_calls.get(),
            0,
            "no evidence line on a failed re-provision"
        );
    }

    #[test]
    fn vxlan_setup_on_single_group_is_a_recorded_no_op() {
        use mock::MockLeafRunner;
        let a = MockLeafRunner::default();
        let runners = runner_map(&[("a", &a)]);
        let handle = VxlanSubstrateProvider
            .setup(
                &topology(&[("a", "192.168.64.10"), ("b", "192.168.64.11")]),
                &runners,
            )
            .expect("single group is a no-op, not an error");
        assert!(!handle.record.provisioned);
        assert!(handle.overlay_ips.is_empty());
        assert!(a.recorded().is_empty(), "no leaf command may run");
        // And teardown of that handle issues nothing.
        VxlanSubstrateProvider
            .teardown(&handle, &runners)
            .expect("no-op teardown");
        assert!(a.recorded().is_empty());
    }

    // ── CN-1 §0.1 additions: in_netns, supports(), endpoint() ──────────

    /// `in_netns` must produce exactly `ip netns exec <ns> <argv…>` — the
    /// argv-only form. Verified through the runner's own recording, so a
    /// backend that rebuilt the prefix differently would be caught.
    #[test]
    fn in_netns_prefixes_ip_netns_exec_and_preserves_argv() {
        let runner = mock::MockLeafRunner::default();
        let output = runner
            .in_netns("site-a-router", &["nft", "list", "ruleset"])
            .expect("in_netns runs");
        assert!(output.success);
        assert_eq!(
            runner.recorded(),
            vec![vec![
                "ip".to_owned(),
                "netns".to_owned(),
                "exec".to_owned(),
                "site-a-router".to_owned(),
                "nft".to_owned(),
                "list".to_owned(),
                "ruleset".to_owned(),
            ]]
        );
    }

    /// Negative path: a namespace name that could smuggle an option, a path
    /// component, or a shell metacharacter is rejected BEFORE any command
    /// runs. The runner must record zero calls — rejection, not execution.
    #[test]
    fn in_netns_rejects_hostile_namespace_names_without_running_anything() {
        let hostile = [
            "",
            ".",
            "..",
            "-rf",
            "site a",
            "site;reboot",
            "site$(id)",
            "../../etc/passwd",
            "site\nnext",
        ];
        for name in hostile {
            let runner = mock::MockLeafRunner::default();
            let err = runner
                .in_netns(name, &["ip", "addr"])
                .expect_err("hostile namespace name must be rejected");
            assert!(
                err.contains("network namespace name"),
                "unexpected error for {name:?}: {err}"
            );
            assert!(
                runner.recorded().is_empty(),
                "{name:?} must not reach the runner"
            );
        }
        // A 256-byte name exceeds the /var/run/netns filename bound.
        let runner = mock::MockLeafRunner::default();
        assert!(
            runner
                .in_netns(&"a".repeat(256), &["ip", "addr"])
                .expect_err("over-long namespace name must be rejected")
                .contains("exceeds")
        );
        assert!(runner.recorded().is_empty());
    }

    /// Negative path: argv validation still applies inside a namespace.
    #[test]
    fn in_netns_rejects_empty_and_control_char_argv() {
        let runner = mock::MockLeafRunner::default();
        assert!(
            runner
                .in_netns("ns0", &[])
                .expect_err("empty argv must be rejected")
                .contains("must not be empty")
        );
        assert!(
            runner
                .in_netns("ns0", &["ip", "addr\n; reboot"])
                .expect_err("control chars must be rejected")
                .contains("control characters")
        );
        assert!(runner.recorded().is_empty());
    }

    /// A namespace-scoped failure propagates the leaf command's own exit
    /// status, not a transport error — the two arms stay distinguishable.
    #[test]
    fn in_netns_reports_leaf_exit_status_and_transport_failure_separately() {
        let failing = mock::MockLeafRunner {
            fail_on: vec![0],
            failure_stderr: "Cannot open network namespace \"ns0\"".to_owned(),
            ..mock::MockLeafRunner::default()
        };
        let output = failing.in_netns("ns0", &["ip", "addr"]).expect("Ok arm");
        assert!(!output.success);
        assert!(output.stderr.contains("Cannot open network namespace"));

        let unreachable = mock::MockLeafRunner {
            transport_error_on: vec![0],
            ..mock::MockLeafRunner::default()
        };
        assert!(
            unreachable
                .in_netns("ns0", &["ip", "addr"])
                .expect_err("transport failure is the Err arm")
                .contains("mock transport failure")
        );
    }

    #[test]
    fn nat_profile_id_accepts_only_the_known_vocabulary() {
        for known in KNOWN_NAT_PROFILES {
            let parsed = NatProfileId::parse(known).expect("known profile parses");
            assert_eq!(parsed.as_str(), *known);
            assert_eq!(parsed.to_string(), *known);
        }
        // Surrounding whitespace is trimmed, not treated as a new profile.
        assert_eq!(
            NatProfileId::parse("  full_cone ").expect("trims").as_str(),
            "full_cone"
        );
    }

    /// Negative path: an unknown profile must fail closed rather than becoming
    /// an opaque string a substrate could later claim to support.
    #[test]
    fn nat_profile_id_rejects_unknown_profiles() {
        for bad in [
            "",
            "FULL_CONE",
            "full-cone",
            "baseline_lan_v2",
            "symmetric;",
        ] {
            let err = NatProfileId::parse(bad).expect_err("unknown profile must be rejected");
            assert!(err.contains("unknown NAT profile"), "{bad:?}: {err}");
        }
    }

    /// The CN-4 `supports()` matrix for vxlan, widened in the SAME change that
    /// wired `apply_nat_profile`: the flat overlay plus the router namespace
    /// realise four of the five profiles, and `double_nat_cgnat` stays a
    /// reasoned refusal because a vxlan site has exactly one router hop.
    #[test]
    fn vxlan_supports_the_four_single_router_profiles_and_explains_the_refusal() {
        let provider = VxlanSubstrateProvider;
        for supported in [
            "baseline_lan",
            "port_restricted_cone",
            "full_cone",
            "symmetric",
        ] {
            let support = provider.supports(&profile(supported));
            assert_eq!(support, Support::Supported, "{supported} must be claimed");
            assert!(support.reason().is_none());
        }
        let cgnat = provider.supports(&profile("double_nat_cgnat"));
        assert!(!cgnat.is_supported());
        assert!(
            cgnat.reason().expect("reason").contains("carrier chain"),
            "double_nat_cgnat refusal must state the topological reason"
        );
    }

    // ── CN-4: NatModifiers, SiteRef, apply_nat_profile ─────────────────

    fn profile(name: &str) -> NatProfileId {
        NatProfileId::parse(name).expect("known profile")
    }

    fn site(name: &str) -> SiteRef {
        SiteRef::new(name).expect("valid site reference")
    }

    /// A provisioned two-node handle, as `setup` would leave it.
    fn provisioned_handle() -> SubstrateHandle {
        SubstrateHandle {
            record: SubstrateRecord {
                substrate_id: "vxlan".to_owned(),
                topology_digest: "digest".to_owned(),
                provisioned: true,
                participants: vec!["lenovo-1".to_owned(), "utm-1".to_owned()],
            },
            overlay_ips: BTreeMap::from([
                ("lenovo-1".to_owned(), "172.20.10.2".to_owned()),
                ("utm-1".to_owned(), "172.20.20.2".to_owned()),
            ]),
            underlay_ips: BTreeMap::from([
                ("lenovo-1".to_owned(), "192.168.0.30".to_owned()),
                ("utm-1".to_owned(), "192.168.64.10".to_owned()),
            ]),
            created_resources: vec![
                CreatedResource::link("lenovo-1", VXLAN_LINK_NAME),
                CreatedResource::link("utm-1", VXLAN_LINK_NAME),
            ],
        }
    }

    fn joined(runner: &mock::MockLeafRunner) -> Vec<String> {
        runner
            .recorded()
            .into_iter()
            .map(|argv| argv.join(" "))
            .collect()
    }

    /// A mock whose `lab-substrate-capability` probe answers yes — what a
    /// correctly built guest daemon prints.
    fn capability_runner() -> mock::MockLeafRunner {
        mock::MockLeafRunner {
            stdout_by_match: vec![(
                "lab-substrate-capability".to_owned(),
                "lab-substrate=yes\n".to_owned(),
            )],
            ..mock::MockLeafRunner::default()
        }
    }

    /// A mock whose `ip route get` answers with a real device line — what
    /// every attestation-writing path derives the underlay interface from.
    fn route_answer_runner() -> mock::MockLeafRunner {
        mock::MockLeafRunner {
            stdout_by_match: vec![(
                "route get".to_owned(),
                "192.168.64.10 dev mgmt0 src 192.168.0.30 uid 0\n".to_owned(),
            )],
            ..mock::MockLeafRunner::default()
        }
    }

    /// A guest mock that passes the provision-time capability probe AND
    /// answers the route-get derivation — the minimum for a happy setup.
    fn substrate_ready_runner() -> mock::MockLeafRunner {
        let mut runner = capability_runner();
        runner
            .stdout_by_match
            .push(("route get".to_owned(), route_answer_stdout()));
        runner
    }

    fn route_answer_stdout() -> String {
        "192.168.64.10 dev mgmt0 src 192.168.0.30 uid 0\n".to_owned()
    }

    /// The three calls that open every participant's teardown (finding 16):
    /// idempotent attestation removal, the best-effort crash-loop limit
    /// reset, then the daemon restart that rebuilds the boot table without
    /// the transit rule. All precede ANY link delete.
    fn substrate_teardown_head() -> Vec<String> {
        vec![
            format!("sudo -n {GUEST_RUSTYNET_CLI} ops vm-lab-remove-substrate-transit"),
            "sudo -n systemctl reset-failed rustynetd".to_owned(),
            "sudo -n systemctl restart rustynetd".to_owned(),
        ]
    }

    /// The two fail-closed residue probes that close every participant's
    /// teardown, after the link deletions and the egress-pin revert.
    fn substrate_teardown_tail() -> Vec<String> {
        vec![
            "sudo -n nft list ruleset".to_owned(),
            format!("sudo -n test ! -e {SUBSTRATE_TRANSIT_ATTESTATION_PATH}"),
        ]
    }

    #[test]
    fn nat_modifiers_default_to_none_and_describe_themselves() {
        let none = NatModifiers::none();
        assert!(none.is_empty());
        assert!(!none.upnp_available());
        assert_eq!(none.ipv6_prefix(), None);
        assert_eq!(none.describe(), "none");

        let both = NatModifiers::none()
            .with_upnp()
            .with_ipv6_prefix("fd77:1::/64")
            .expect("a ULA prefix is accepted");
        assert!(!both.is_empty());
        assert!(both.upnp_available());
        assert_eq!(both.ipv6_prefix(), Some("fd77:1::/64"));
        assert_eq!(both.describe(), "upnp_available+ipv6=fd77:1::/64");
    }

    /// Negative path: the v6 modifier is the only modifier carrying operator
    /// data, so it fails closed on everything malformed — and on a GLOBAL
    /// prefix, because a lab must not advertise routes for address space it
    /// does not own.
    #[test]
    fn nat_modifiers_reject_malformed_and_non_ula_ipv6_prefixes() {
        for bad in [
            "fd77:1::",
            "fd77:1::/",
            "fd77:1::/0",
            "fd77:1::/129",
            "fd77:1::/128",
            "not-an-address/64",
            // Global unicast: a real, routable prefix.
            "2001:db8::/64",
            // Link-local, also outside fc00::/7.
            "fe80::/64",
            // Not a network address — ::1 and ::2 are this crate's to assign.
            "fd77:1::5/64",
        ] {
            assert!(
                NatModifiers::none().with_ipv6_prefix(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn site_ref_rejects_names_that_could_smuggle_an_option_or_a_path() {
        for bad in ["", "  ", "-rf", "site a", "site;reboot", "../etc", "a/b"] {
            assert!(SiteRef::new(bad).is_err(), "{bad:?} must be rejected");
        }
        assert_eq!(site(" utm-1 ").as_str(), "utm-1", "surrounding space trims");
        assert_eq!(site("utm-1").to_string(), "utm-1");
    }

    /// The site LAN a NAT'd node sits on is derived from its (unique) overlay
    /// address, so two nodes can never collide on it.
    #[test]
    fn site_addressing_is_derived_uniquely_from_the_overlay_address() {
        let a = SiteAddressing::for_overlay(Ipv4Addr::new(172, 20, 10, 2));
        let b = SiteAddressing::for_overlay(Ipv4Addr::new(172, 20, 20, 2));
        assert_eq!(a.overlay_cidr, "172.20.10.2/16");
        assert_eq!(a.gateway_ip, "10.10.2.1");
        assert_eq!(a.host_ip, "10.10.2.2");
        assert_eq!(a.host_cidr, "10.10.2.2/24");
        assert_ne!(a.host_ip, b.host_ip);
        assert_ne!(a.gateway_ip, b.gateway_ip);
    }

    /// Per-profile rule shape: each of the three shaping profiles installs
    /// exactly the `apply_nat_profile.sh` ruleset, inside the router namespace,
    /// on the vxlan device.
    #[test]
    fn vxlan_apply_installs_the_documented_rule_shape_per_profile() {
        let expectations: &[(&str, &str)] = &[
            (
                "port_restricted_cone",
                "nft add rule ip rustynet_vxnat post oifname rustynet-vx0 masquerade",
            ),
            (
                "symmetric",
                "nft add rule ip rustynet_vxnat post oifname rustynet-vx0 masquerade random",
            ),
            (
                "full_cone",
                "nft add rule ip rustynet_vxnat pre iifname rustynet-vx0 udp dport \
                 51820-51900 dnat to 10.10.2.2",
            ),
        ];
        for (name, expected_rule) in expectations {
            let runner = route_answer_runner();
            let runners = runner_map(&[("lenovo-1", &runner)]);
            let mut handle = provisioned_handle();
            VxlanSubstrateProvider
                .apply_nat_profile(
                    &mut handle,
                    &site("lenovo-1"),
                    &profile(name),
                    &NatModifiers::none(),
                    &runners,
                )
                .unwrap_or_else(|err| panic!("{name} must apply: {err}"));
            let calls = joined(&runner);
            assert!(
                calls.iter().any(|call| call.ends_with(expected_rule)),
                "{name} must install {expected_rule:?}; got {calls:#?}"
            );
            // Applying a shaping profile REWRITES the attestation so the
            // daemon-facing overlay becomes the site LAN veth.
            assert!(
                calls.iter().any(|call| call
                    .contains("vm-lab-write-substrate-transit --overlay-interface rustynet-vxl")),
                "{name} must re-attest against {VXLAN_SITE_LAN_IF}: {calls:#?}"
            );
            // Every rule lands inside the router namespace, never in the root
            // namespace where it would NAT the guest's management traffic.
            assert!(
                calls
                    .iter()
                    .filter(|call| call.contains("nft add"))
                    .all(|call| call.contains(&format!("ip netns exec {VXLAN_ROUTER_NS}"))),
                "every nft rule must run inside {VXLAN_ROUTER_NS}; got {calls:#?}"
            );
            // `symmetric` must NOT be reachable as a plain masquerade and vice
            // versa — the distinguishing token is the whole profile.
            let has_random = calls.iter().any(|call| call.ends_with("masquerade random"));
            assert_eq!(
                has_random,
                *name == "symmetric",
                "only symmetric randomises source ports; {name} got {calls:#?}"
            );
            // The node keeps the overlay address peers were handed — now as the
            // router's WAN address.
            assert!(
                calls.iter().any(|call| call.contains(&format!(
                    "ip netns exec {VXLAN_ROUTER_NS} sudo -n ip addr replace 172.20.10.2/16 dev \
                     {VXLAN_LINK_NAME}"
                ))),
                "the router must keep the node's overlay address: {calls:#?}"
            );
            // And the created objects are recorded for teardown.
            assert!(
                handle
                    .created_resources
                    .contains(&CreatedResource::netns("lenovo-1", VXLAN_ROUTER_NS))
                    && handle
                        .created_resources
                        .contains(&CreatedResource::link("lenovo-1", VXLAN_SITE_LAN_IF)),
                "{:?}",
                handle.created_resources
            );
        }
    }

    /// `baseline_lan` is the reset: it removes the router namespace and the
    /// site LAN and puts the overlay address back on the flat device — and
    /// installs no NAT rule at all.
    #[test]
    fn vxlan_apply_baseline_lan_unwinds_the_nat_boundary_completely() {
        let runner = route_answer_runner();
        let runners = runner_map(&[("lenovo-1", &runner)]);
        let mut handle = provisioned_handle();
        VxlanSubstrateProvider
            .apply_nat_profile(
                &mut handle,
                &site("lenovo-1"),
                &profile("baseline_lan"),
                &NatModifiers::none(),
                &runners,
            )
            .expect("baseline_lan applies");
        let calls = joined(&runner);
        assert!(
            calls.iter().all(|call| !call.contains("nft")),
            "baseline_lan installs no NAT rule: {calls:#?}"
        );
        assert!(
            calls
                .iter()
                .any(|call| call.contains(&format!("ip netns del {VXLAN_ROUTER_NS}")))
                && calls
                    .iter()
                    .any(|call| call.contains(&format!("ip link del {VXLAN_SITE_LAN_IF}"))),
            "baseline_lan must remove the router namespace and the site LAN: {calls:#?}"
        );
        // The reset re-attests against the flat vxlan link again.
        assert!(
            calls.iter().any(|call| call
                .contains("vm-lab-write-substrate-transit --overlay-interface rustynet-vx0")),
            "baseline_lan must re-attest against {VXLAN_LINK_NAME}: {calls:#?}"
        );
        assert_eq!(
            handle.created_resources,
            [
                CreatedResource::link("lenovo-1", VXLAN_LINK_NAME),
                CreatedResource::link("utm-1", VXLAN_LINK_NAME),
            ],
            "the removed objects must stop being recorded as created"
        );
    }

    /// The transit alias is a pure, injective map into the benchmarking
    /// range: same last two octets, always 198.18 (inside 198.18.0.0/15),
    /// never colliding across distinct overlays.
    #[test]
    fn transit_alias_is_deterministic_and_stays_in_the_benchmarking_pool() {
        assert_eq!(
            transit_alias_ip(Ipv4Addr::new(172, 20, 10, 2)),
            Ipv4Addr::new(198, 18, 10, 2)
        );
        assert_eq!(
            transit_alias_ip(Ipv4Addr::new(172, 20, 240, 254)),
            Ipv4Addr::new(198, 18, 240, 254)
        );
        for overlay in [
            Ipv4Addr::new(172, 20, 10, 2),
            Ipv4Addr::new(172, 20, 20, 2),
            Ipv4Addr::new(172, 20, 130, 200),
        ] {
            let alias = transit_alias_ip(overlay);
            let [a0, a1, a2, a3] = alias.octets();
            let [o2, o3] = [overlay.octets()[2], overlay.octets()[3]];
            assert_eq!([a0, a1], [198, 18], "{alias} must sit in 198.18.0.0/15");
            assert_eq!([a2, a3], [o2, o3], "{alias} must keep the overlay tail");
        }
        assert_ne!(
            transit_alias_ip(Ipv4Addr::new(172, 20, 10, 2)),
            transit_alias_ip(Ipv4Addr::new(172, 20, 10, 3))
        );
        // The relay guest resolution accepts exactly ONE 198.18/15 address,
        // so uniqueness per participant is load-bearing, not cosmetic.
        let aliases = [
            transit_alias_ip(Ipv4Addr::new(172, 20, 10, 2)),
            transit_alias_ip(Ipv4Addr::new(172, 20, 20, 2)),
            transit_alias_ip(Ipv4Addr::new(172, 20, 30, 2)),
        ];
        for (i, left) in aliases.iter().enumerate() {
            for right in aliases.iter().skip(i + 1) {
                assert_ne!(left, right);
            }
        }
    }

    /// Every participant gets EXACTLY ONE transit-alias argv, on the same
    /// vxlan device, after the primary overlay address and before the link
    /// comes up — and the alias adds no created resource of its own (it
    /// dies with the device).
    #[test]
    fn vxlan_setup_adds_exactly_one_transit_alias_per_node_after_the_primary() {
        let lenovo = route_answer_runner();
        let utm1 = route_answer_runner();
        let utm2 = route_answer_runner();
        let runners = runner_map(&[("lenovo-1", &lenovo), ("utm-1", &utm1), ("utm-2", &utm2)]);
        let handle = VxlanSubstrateProvider
            .setup(&two_lan_topology(), &runners)
            .expect("setup");
        for runner in [&lenovo, &utm1, &utm2] {
            let calls = joined(runner);
            let alias_calls = calls
                .iter()
                .filter(|call| call.contains("ip addr replace 198.18."))
                .count();
            assert_eq!(alias_calls, 1, "exactly one alias argv: {calls:#?}");
            let overlay_at = calls
                .iter()
                .position(|call| call.contains("ip addr replace 172.20."))
                .expect("overlay addr argv");
            let alias_at = calls
                .iter()
                .position(|call| call.contains("ip addr replace 198.18."))
                .expect("alias addr argv");
            let up_at = calls
                .iter()
                .position(|call| call.contains("ip link set rustynet-vx0 up"))
                .expect("link up argv");
            assert!(
                overlay_at < alias_at && alias_at < up_at,
                "alias must follow the primary and precede link-up: {calls:#?}"
            );
        }
        // The alias is an address on the SAME device, never a new interface.
        assert_eq!(handle.created_resources.len(), 3);
        assert!(
            handle
                .created_resources
                .iter()
                .all(|resource| !format!("{resource:?}").contains("198.18.")),
            "the alias must not be recorded as a created resource: {:?}",
            handle.created_resources
        );
    }

    /// A NAT'd site must carry the transit alias across the boundary exactly
    /// like the overlay pool: the alias re-attached to the router's WAN
    /// device inside the namespace, and the whole 198.18.0.0/16 pool routed
    /// through the site LAN alongside 172.20.0.0/16.
    #[test]
    fn vxlan_nat_sites_route_and_carry_the_transit_alias_across_the_boundary() {
        for name in ["port_restricted_cone", "full_cone", "symmetric"] {
            let runner = route_answer_runner();
            let runners = runner_map(&[("lenovo-1", &runner)]);
            let mut handle = provisioned_handle();
            VxlanSubstrateProvider
                .apply_nat_profile(
                    &mut handle,
                    &site("lenovo-1"),
                    &profile(name),
                    &NatModifiers::none(),
                    &runners,
                )
                .unwrap_or_else(|err| panic!("{name} must apply: {err}"));
            let calls = joined(&runner);
            assert!(
                calls.iter().any(|call| call.contains(&format!(
                    "ip netns exec {VXLAN_ROUTER_NS} sudo -n ip addr replace 198.18.10.2/16 dev \
                     {VXLAN_LINK_NAME}"
                ))),
                "{name}: the router must re-attach the transit alias: {calls:#?}"
            );
            assert!(
                calls.iter().any(|call| call.contains(&format!(
                    "sudo -n ip route replace {TRANSIT_ALIAS_POOL_CIDR} via 10.10.2.1 dev \
                     {VXLAN_SITE_LAN_IF}"
                ))),
                "{name}: the transit pool must follow the overlay pool through the router: \
                 {calls:#?}"
            );
        }
    }

    /// `baseline_lan` moves the device back to the root namespace, which
    /// drops every address — the reset must re-assert the transit alias on
    /// the flat device, not just the overlay address.
    #[test]
    fn vxlan_baseline_lan_restores_the_transit_alias_on_the_flat_device() {
        let runner = route_answer_runner();
        let runners = runner_map(&[("lenovo-1", &runner)]);
        let mut handle = provisioned_handle();
        VxlanSubstrateProvider
            .apply_nat_profile(
                &mut handle,
                &site("lenovo-1"),
                &profile("baseline_lan"),
                &NatModifiers::none(),
                &runners,
            )
            .expect("baseline_lan applies");
        let calls = joined(&runner);
        assert!(
            calls.iter().any(
                |call| call.contains("sudo -n ip addr replace 198.18.10.2/16 dev rustynet-vx0")
            ),
            "the flat reset must re-assert the transit alias: {calls:#?}"
        );
    }

    /// The alias is swept by the SAME teardown that removes the device: no
    /// extra residue probe is needed and none may appear.
    #[test]
    fn vxlan_teardown_sweeps_the_transit_alias_with_the_device() {
        let lenovo = substrate_ready_runner();
        let utm1 = substrate_ready_runner();
        let utm2 = substrate_ready_runner();
        let runners = runner_map(&[("lenovo-1", &lenovo), ("utm-1", &utm1), ("utm-2", &utm2)]);
        let handle = VxlanSubstrateProvider
            .setup(&two_lan_topology(), &runners)
            .expect("setup");
        VxlanSubstrateProvider
            .teardown(&handle, &runners)
            .expect("teardown owns the alias through the device delete");
        for runner in [&lenovo, &utm1, &utm2] {
            let calls = joined(runner);
            assert!(
                calls
                    .iter()
                    .any(|call| call.contains("ip link del rustynet-vx0")),
                "the device delete is what removes the alias: {calls:#?}"
            );
            assert!(
                !calls
                    .iter()
                    .any(|call| call.contains("198.18.") && call.contains("ip addr del")),
                "no alias-specific delete argv exists: {calls:#?}"
            );
        }
    }

    /// Application/removal symmetry: applying a shaping profile with modifiers
    /// and then resetting to `baseline_lan` leaves the recorded resource list
    /// exactly as it started, and re-applying is idempotent rather than
    /// additive.
    #[test]
    fn vxlan_apply_and_reset_are_symmetric_and_idempotent() {
        let runner = route_answer_runner();
        let runners = runner_map(&[("lenovo-1", &runner)]);
        let mut handle = provisioned_handle();
        let before = handle.created_resources.clone();
        let modifiers = NatModifiers::none()
            .with_upnp()
            .with_ipv6_prefix("fd77:1::/64")
            .expect("ULA prefix");

        for _ in 0..2 {
            VxlanSubstrateProvider
                .apply_nat_profile(
                    &mut handle,
                    &site("lenovo-1"),
                    &profile("full_cone"),
                    &modifiers,
                    &runners,
                )
                .expect("apply");
            // Re-applying must not accumulate duplicate resources: the reset at
            // the head of every apply drops what the previous one created.
            assert_eq!(
                handle.created_resources.len(),
                before.len() + 2,
                "{:?}",
                handle.created_resources
            );
        }

        VxlanSubstrateProvider
            .apply_nat_profile(
                &mut handle,
                &site("lenovo-1"),
                &profile("baseline_lan"),
                &NatModifiers::none(),
                &runners,
            )
            .expect("reset");
        assert_eq!(
            handle.created_resources, before,
            "reset must restore the pre-NAT resource list exactly"
        );
    }

    /// The modifiers `vxlan_tier_b.sh` silently dropped are now real leaf ops:
    /// a uPnP responder on the site LAN and a natively routed ULA prefix.
    #[test]
    fn vxlan_apply_wires_the_upnp_and_ipv6_modifiers() {
        let runner = route_answer_runner();
        let runners = runner_map(&[("lenovo-1", &runner)]);
        let mut handle = provisioned_handle();
        VxlanSubstrateProvider
            .apply_nat_profile(
                &mut handle,
                &site("lenovo-1"),
                &profile("port_restricted_cone"),
                &NatModifiers::none()
                    .with_upnp()
                    .with_ipv6_prefix("fd77:1::/64")
                    .expect("ULA prefix"),
                &runners,
            )
            .expect("apply with modifiers");
        let calls = joined(&runner);
        assert!(
            calls.iter().any(|call| call
                == &format!(
                    "ip netns exec {VXLAN_ROUTER_NS} sudo -n miniupnpd -i {VXLAN_LINK_NAME} -a \
                     10.10.2.1 -N"
                )),
            "uPnP must listen on the site LAN gateway and map through the overlay device: \
             {calls:#?}"
        );
        assert!(
            calls
                .iter()
                .any(|call| call.contains("net.ipv6.conf.all.forwarding=1"))
                && calls
                    .iter()
                    .any(|call| call.contains("ip -6 addr replace fd77:1::1/64"))
                && calls
                    .iter()
                    .any(|call| call.contains("ip -6 addr replace fd77:1::2/64")),
            "the v6 modifier must address both ends of the site LAN and forward: {calls:#?}"
        );
        assert!(
            calls
                .iter()
                .any(|call| call.contains("ip -6 route replace default via fd77:1::1")),
            "the v6 path must be routed natively — no NAT66: {calls:#?}"
        );
        assert!(
            calls
                .iter()
                .all(|call| !call.contains("ip6") && !call.contains("masquerade\tv6")),
            "no NAT66 rule may be installed: {calls:#?}"
        );
    }

    /// Fail closed: an unsupported profile/modifier combination is a TYPED
    /// refusal decided before the first leaf command, so there is never a
    /// half-applied ruleset to unwind.
    #[test]
    fn vxlan_refuses_unsupported_combinations_without_touching_the_guest() {
        use mock::MockLeafRunner;
        // (a) an unsupported PROFILE.
        let runner = MockLeafRunner::default();
        let runners = runner_map(&[("lenovo-1", &runner)]);
        let mut handle = provisioned_handle();
        let err = VxlanSubstrateProvider
            .apply_nat_profile(
                &mut handle,
                &site("lenovo-1"),
                &profile("double_nat_cgnat"),
                &NatModifiers::none(),
                &runners,
            )
            .expect_err("double_nat_cgnat is out of reach for a vxlan site");
        assert!(
            matches!(err, NatApplyError::Refused(Support::UnsupportedByDesign(_))),
            "{err:?}"
        );
        assert!(runner.recorded().is_empty(), "a refusal must run nothing");

        // (b) a supported profile with an unsupported MODIFIER combination.
        let runner = MockLeafRunner::default();
        let runners = runner_map(&[("lenovo-1", &runner)]);
        let err = VxlanSubstrateProvider
            .apply_nat_profile(
                &mut handle,
                &site("lenovo-1"),
                &profile("baseline_lan"),
                &NatModifiers::none().with_upnp(),
                &runners,
            )
            .expect_err("baseline_lan builds no router for a uPnP responder to sit on");
        match &err {
            NatApplyError::Refused(Support::UnsupportedModifier { modifier, reason }) => {
                assert_eq!(modifier, "upnp_available");
                assert!(reason.contains("no router namespace"), "{reason}");
            }
            other => panic!("expected a modifier refusal, got {other:?}"),
        }
        assert!(runner.recorded().is_empty(), "a refusal must run nothing");
        assert_eq!(
            handle.created_resources.len(),
            provisioned_handle().created_resources.len(),
            "a refusal must not change the recorded resources"
        );
    }

    /// Fail closed on a site this substrate never provisioned, and on a handle
    /// that provisioned no overlay at all.
    #[test]
    fn vxlan_apply_fails_closed_on_an_unknown_site_or_unprovisioned_handle() {
        use mock::MockLeafRunner;
        let runner = MockLeafRunner::default();
        let runners = runner_map(&[("lenovo-1", &runner)]);

        let mut handle = provisioned_handle();
        let err = VxlanSubstrateProvider
            .apply_nat_profile(
                &mut handle,
                &site("not-a-node"),
                &profile("symmetric"),
                &NatModifiers::none(),
                &runners,
            )
            .expect_err("an unknown site must fail");
        assert!(matches!(err, NatApplyError::Failed(_)), "{err:?}");
        assert!(err.message().contains("not a participating node"), "{err}");

        let mut unprovisioned = provisioned_handle();
        unprovisioned.record.provisioned = false;
        let err = VxlanSubstrateProvider
            .apply_nat_profile(
                &mut unprovisioned,
                &site("lenovo-1"),
                &profile("symmetric"),
                &NatModifiers::none(),
                &runners,
            )
            .expect_err("an unprovisioned handle must fail");
        assert!(err.message().contains("provisioned no overlay"), "{err}");
        assert!(runner.recorded().is_empty());
    }

    /// Teardown must remove the NAT resources `apply_nat_profile` created, with
    /// the RIGHT verb per kind and the namespace before the interfaces recorded
    /// under it — otherwise a router namespace holding the vxlan device is left
    /// on the guest as release-blocking residue.
    #[test]
    fn vxlan_teardown_sweeps_the_nat_resources_with_the_right_verb() {
        use mock::MockLeafRunner;
        let apply_runner = route_answer_runner();
        let apply_runners = runner_map(&[("lenovo-1", &apply_runner)]);
        let mut handle = provisioned_handle();
        // Only one node is NAT'd, so teardown must still cover the other's
        // plain vxlan link.
        VxlanSubstrateProvider
            .apply_nat_profile(
                &mut handle,
                &site("lenovo-1"),
                &profile("symmetric"),
                &NatModifiers::none(),
                &apply_runners,
            )
            .expect("apply");

        let lenovo = MockLeafRunner::default();
        let utm = MockLeafRunner::default();
        let runners = runner_map(&[("lenovo-1", &lenovo), ("utm-1", &utm)]);
        VxlanSubstrateProvider
            .teardown(&handle, &runners)
            .expect("teardown");
        let mut expected_lenovo = substrate_teardown_head();
        expected_lenovo.extend([
            format!("sudo -n ip link del {VXLAN_SITE_LAN_IF}"),
            format!("sudo -n ip netns del {VXLAN_ROUTER_NS}"),
            format!("sudo -n ip link del {VXLAN_LINK_NAME}"),
            format!(
                "sudo -n sed -i -e /^RUSTYNET_EGRESS_INTERFACE={VXLAN_LINK_NAME}$/d \
                 -e /^RUSTYNET_EGRESS_INTERFACE={VXLAN_SITE_LAN_IF}$/d {DAEMON_ENV_FILE}"
            ),
        ]);
        expected_lenovo.extend(substrate_teardown_tail());
        assert_eq!(
            joined(&lenovo),
            expected_lenovo,
            "reverse creation order, and `ip netns del` for the namespace"
        );
        let mut expected_utm = substrate_teardown_head();
        expected_utm.extend([
            format!("sudo -n ip link del {VXLAN_LINK_NAME}"),
            format!(
                "sudo -n sed -i -e /^RUSTYNET_EGRESS_INTERFACE={VXLAN_LINK_NAME}$/d \
                 -e /^RUSTYNET_EGRESS_INTERFACE={VXLAN_SITE_LAN_IF}$/d {DAEMON_ENV_FILE}"
            ),
        ]);
        expected_utm.extend(substrate_teardown_tail());
        assert_eq!(
            joined(&utm),
            expected_utm,
            "the un-NAT'd site still gets its egress pin reverted and its \
             substrate-transit state removed"
        );
    }

    /// Resume case: with only the persisted record, teardown cannot know
    /// whether a NAT profile was applied — so it must target the NAT objects
    /// too, and tolerate their absence.
    #[test]
    fn vxlan_teardown_after_a_resume_targets_the_nat_objects_too() {
        use mock::MockLeafRunner;
        let handle = SubstrateHandle {
            record: SubstrateRecord {
                substrate_id: "vxlan".to_owned(),
                topology_digest: "digest".to_owned(),
                provisioned: true,
                participants: vec!["a".to_owned()],
            },
            overlay_ips: BTreeMap::new(),
            underlay_ips: BTreeMap::new(),
            created_resources: Vec::new(),
        };
        // The namespace and the site LAN were never created on this guest.
        // (Calls 0/1/2 are the attestation removal + limit reset + restart;
        // 3/4 are the netns and site-LAN deletions.)
        let a = MockLeafRunner {
            fail_on: vec![3, 4],
            failure_stderr: "Cannot remove namespace file: No such file or directory".to_owned(),
            ..MockLeafRunner::default()
        };
        let runners = runner_map(&[("a", &a)]);
        VxlanSubstrateProvider
            .teardown(&handle, &runners)
            .expect("absent NAT objects are the idempotent success case");
        let mut expected = substrate_teardown_head();
        expected.extend([
            format!("sudo -n ip netns del {VXLAN_ROUTER_NS}"),
            format!("sudo -n ip link del {VXLAN_SITE_LAN_IF}"),
            format!("sudo -n ip link del {VXLAN_LINK_NAME}"),
            format!(
                "sudo -n sed -i -e /^RUSTYNET_EGRESS_INTERFACE={VXLAN_LINK_NAME}$/d \
                 -e /^RUSTYNET_EGRESS_INTERFACE={VXLAN_SITE_LAN_IF}$/d {DAEMON_ENV_FILE}"
            ),
        ]);
        expected.extend(substrate_teardown_tail());
        assert_eq!(joined(&a), expected);
    }

    /// `endpoint()` prefers the provisioned overlay address, falls back to the
    /// underlay only when there is no overlay, and never invents one.
    #[test]
    fn endpoint_prefers_overlay_falls_back_to_underlay_and_refuses_unknown_aliases() {
        let handle = SubstrateHandle {
            record: vxlan_record(true),
            overlay_ips: BTreeMap::from([("a".to_owned(), "172.20.10.2".to_owned())]),
            underlay_ips: BTreeMap::from([
                ("a".to_owned(), "192.168.64.10".to_owned()),
                ("b".to_owned(), "192.168.0.20".to_owned()),
            ]),
            created_resources: Vec::new(),
        };
        assert_eq!(
            handle.endpoint("a").expect("a resolves"),
            ResolvedEndpoint {
                alias: "a".to_owned(),
                address: "172.20.10.2".to_owned(),
                plane: EndpointPlane::Overlay,
            }
        );
        assert_eq!(
            handle.endpoint("b").expect("b resolves"),
            ResolvedEndpoint {
                alias: "b".to_owned(),
                address: "192.168.0.20".to_owned(),
                plane: EndpointPlane::Underlay,
            }
        );
        assert!(handle.endpoint("missing").is_none());
    }

    #[test]
    fn mock_runner_records_argv_and_scripts_failures() {
        use mock::MockLeafRunner;
        let runner = MockLeafRunner {
            fail_on: vec![1],
            ..MockLeafRunner::default()
        };
        assert!(runner.run(&["ip", "link", "show"]).expect("call 0").success);
        assert!(!runner.run(&["ip", "link", "add"]).expect("call 1").success);
        let calls = runner.recorded();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0], ["ip", "link", "show"]);
    }

    // QH-83: both pass paths of cross_network_substrate_setup must leave a
    // durable stage-log line (the catalog declares this stage StageLog and
    // the runner demotes an unwitnessed PASS). Mutation caught: dropping a
    // witness write or demoting it to best-effort.
    #[test]
    fn substrate_witness_lines_name_the_pass_path_and_scope() {
        let dir = std::env::temp_dir().join(format!(
            "substrate_witness_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&dir);

        CrossNetworkSubstrateSetupStage::write_no_overlay_witness(&dir, 4)
            .expect("no-overlay witness write");
        CrossNetworkSubstrateSetupStage::write_provision_witness(&dir, "vxlan", true, 3)
            .expect("provision witness write");
        CrossNetworkSubstrateSetupStage::write_provision_witness(&dir, "vxlan", false, 0)
            .expect("no-overlay provision witness write");

        let log = std::fs::read_to_string(
            crate::vm_lab::orchestrator::evidence::rust_native_stage_log_path(
                &dir,
                StageId::CrossNetworkSubstrateSetup.as_str(),
            ),
        )
        .expect("stage log readable");
        assert!(
            log.contains(
                "substrate_setup=no-overlay record_match=ok overlay_nodes=0 assignments=4"
            ),
            "{log}"
        );
        assert!(
            log.contains("substrate_setup=vxlan provisioned=true overlay_nodes=3"),
            "{log}"
        );
        assert!(
            log.contains(
                "substrate_setup=vxlan provisioned=false overlay_nodes=0 \
                 no-overlay: all participants share one underlay /24"
            ),
            "{log}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Fail-closed check: a witness write that cannot land must surface as
    /// an error the stage turns into a failure (never a silent pass).
    #[test]
    fn substrate_witness_write_failure_is_propagated() {
        let blocker =
            std::env::temp_dir().join(format!("substrate_witness_blocker_{}", std::process::id()));
        let _ = std::fs::remove_file(&blocker);
        std::fs::write(&blocker, b"not a directory").expect("blocker file");

        let err = CrossNetworkSubstrateSetupStage::write_no_overlay_witness(&blocker, 1)
            .expect_err("write into a regular file path must fail");
        assert!(!err.is_empty());

        let _ = std::fs::remove_file(&blocker);
    }

    /// A vxlan topology whose participants all share one underlay /24
    /// provisions NO overlay. The stage still passes (later scenario stages
    /// skip on that), but the witness must say `provisioned=false
    /// overlay_nodes=0` — not claim nodes that were never provisioned
    /// (a102 CORRECTION 2: the old code witnessed `provisioned=true
    /// overlay_nodes=<runner count>` on every pass path).
    #[test]
    fn no_overlay_vxlan_provision_witnesses_an_honest_no_op() {
        use mock::MockLeafRunner;
        let dir = std::env::temp_dir().join(format!(
            "substrate_no_overlay_witness_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let mut ctx = OrchestrationContext::new(Vec::new(), dir.clone(), "net".to_owned());
        let a = MockLeafRunner::default();
        let runners = runner_map(&[("a", &a)]);
        // One /24 group: plan_overlay returns no plan, so setup provisions
        // nothing and must not touch any leaf runner.
        let topo = topology(&[("a", "192.168.64.10"), ("b", "192.168.64.11")]);
        assert_eq!(
            CrossNetworkSubstrateSetupStage::provision(
                &mut ctx,
                &VxlanSubstrateProvider,
                &topo,
                &runners
            ),
            StageOutcome::Passed,
            "a no-overlay vxlan setup is still a pass"
        );
        assert!(a.recorded().is_empty(), "no overlay, no leaf commands");
        let handle = ctx.substrate.as_ref().expect("handle stored");
        assert!(!handle.record.provisioned);
        assert!(handle.record.participants.is_empty());

        let log = std::fs::read_to_string(
            crate::vm_lab::orchestrator::evidence::rust_native_stage_log_path(
                &dir,
                StageId::CrossNetworkSubstrateSetup.as_str(),
            ),
        )
        .unwrap_or_default();
        assert!(
            log.contains(
                "substrate_setup=vxlan provisioned=false overlay_nodes=0 \
                 no-overlay: all participants share one underlay /24"
            ),
            "witness must report the no-overlay honestly: {log}"
        );
        assert!(!log.contains("provisioned=true"), "{log}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A teardown over a record that provisioned no overlay must PASS while
    /// its evidence line says nothing was removed — a bare pass there would
    /// read as a removal (a102 CORRECTION 2).
    #[test]
    fn teardown_of_an_unprovisioned_record_witnesses_nothing_to_remove() {
        use mock::MockLeafRunner;
        let dir = std::env::temp_dir().join(format!(
            "substrate_teardown_witness_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let mut ctx = OrchestrationContext::new(Vec::new(), dir.clone(), "net".to_owned());
        ctx.substrate_record = Some(vxlan_record(false));
        let td_a = MockLeafRunner::default();
        let td_runners = runner_map(&[("a", &td_a)]);
        assert_eq!(
            CrossNetworkSubstrateTeardownStage::teardown_with(&mut ctx, &td_runners, Some("vxlan")),
            StageOutcome::Passed
        );
        assert!(
            td_a.recorded().is_empty(),
            "nothing was provisioned, so nothing may be removed"
        );
        let log = std::fs::read_to_string(
            crate::vm_lab::orchestrator::evidence::rust_native_stage_log_path(
                &dir,
                StageId::CrossNetworkSubstrateTeardown.as_str(),
            ),
        )
        .unwrap_or_default();
        assert!(
            log.contains("substrate_teardown=nothing-to-remove (not provisioned)"),
            "teardown witness must state there was nothing to remove: {log}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── substrate-transit contract (design D) ────────────────────────────

    /// The capability parse accepts only the exact line, and the refusal is
    /// the design's verbatim text (it names the rebuild that fixes it).
    #[test]
    fn substrate_capability_parse_and_refusal_text() {
        assert!(parse_substrate_capability("lab-substrate=yes\n"));
        assert!(parse_substrate_capability("\n  lab-substrate=yes  \n\n"));
        assert!(!parse_substrate_capability("lab-substrate=no\n"));
        assert!(!parse_substrate_capability(""));
        assert!(!parse_substrate_capability(
            "error: unrecognized subcommand 'lab-substrate-capability'\n"
        ));
        assert_eq!(
            substrate_capability_refusal("utm-1"),
            "guest rustynetd on utm-1 was built without the lab-substrate feature, \
             which --cross-network-substrate vxlan needs; rebuild the lab binaries with \
             --features rustynetd/lab-substrate (the host-cross build does this by default)"
        );
    }

    /// Provision refuses BEFORE anything is created when any participant's
    /// daemon lacks the feature — and no leaf command may have run.
    #[test]
    fn provision_refuses_when_a_guest_daemon_lacks_lab_substrate() {
        use mock::MockLeafRunner;
        let mut ctx = empty_ctx();
        // Default mocks answer the capability probe with empty stdout: a
        // binary without the subcommand.
        let a = MockLeafRunner::default();
        let b = MockLeafRunner::default();
        let runners = runner_map(&[("a", &a), ("b", &b)]);
        let topo = topology(&[("a", "192.168.64.10"), ("b", "192.168.0.30")]);
        let outcome = CrossNetworkSubstrateSetupStage::provision(
            &mut ctx,
            &VxlanSubstrateProvider,
            &topo,
            &runners,
        );
        let StageOutcome::Failed(message) = outcome else {
            panic!("provision must refuse: {outcome:?}")
        };
        assert!(
            message.contains("was built without the lab-substrate feature"),
            "{message}"
        );
        assert!(
            message.contains("--features rustynetd/lab-substrate"),
            "{message}"
        );
        assert!(
            a.recorded().len() == 1
                && a.recorded()[0].contains(&"lab-substrate-capability".to_owned()),
            "the refusal must run only the capability probe: {:?}",
            a.recorded()
        );
        assert!(ctx.substrate.is_none());
    }

    /// A capability probe that fails (transport error or non-zero exit) is
    /// "no" — fail closed.
    #[test]
    fn substrate_capability_probe_fails_closed() {
        use mock::MockLeafRunner;
        let transport = MockLeafRunner {
            transport_error_on: vec![0],
            ..MockLeafRunner::default()
        };
        assert!(!VxlanSubstrateProvider::guest_substrate_capability(
            &transport
        ));
        let failing = MockLeafRunner {
            fail_on: vec![0],
            ..MockLeafRunner::default()
        };
        assert!(!VxlanSubstrateProvider::guest_substrate_capability(
            &failing
        ));
        // A non-zero exit that STILL prints the capability line is not a
        // capability: the exit status is part of the contract (a crashed or
        // partially failing probe must not read as "yes").
        let failing_but_says_yes = MockLeafRunner {
            fail_on: vec![0],
            stdout_by_match: vec![(
                "lab-substrate-capability".to_owned(),
                "lab-substrate=yes\n".to_owned(),
            )],
            ..MockLeafRunner::default()
        };
        assert!(!VxlanSubstrateProvider::guest_substrate_capability(
            &failing_but_says_yes
        ));
        let yes = capability_runner();
        assert!(VxlanSubstrateProvider::guest_substrate_capability(&yes));
    }

    /// The residue check is fail-closed on both classes and quiet only when
    /// both are clean.
    #[test]
    fn substrate_residue_check_fails_closed() {
        assert!(substrate_residue_errors("", false).is_empty());
        let ruleset = "table inet rustynet_g1 {\n  chain x { oifname \"wlp3s0\" ip daddr \
             192.168.64.10 udp sport 4789 udp dport 4789 counter accept comment \
             \"rustynet_substrate_transit\" }\n}";
        let errors = substrate_residue_errors(ruleset, false);
        assert_eq!(errors.len(), 1);
        assert!(
            errors[0].contains("rustynet_substrate_transit"),
            "{errors:?}"
        );
        let errors = substrate_residue_errors("", true);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("substrate-transit"), "{errors:?}");
        assert_eq!(substrate_residue_errors(ruleset, true).len(), 2);
    }

    /// Teardown FAILS when the daemon's transit rules or the attestation
    /// survive — reporting both residue classes, naming the alias.
    #[test]
    fn teardown_fails_when_substrate_residue_remains() {
        use mock::MockLeafRunner;
        let handle = SubstrateHandle {
            record: SubstrateRecord {
                substrate_id: "vxlan".to_owned(),
                topology_digest: "digest".to_owned(),
                provisioned: true,
                participants: vec!["a".to_owned()],
            },
            overlay_ips: BTreeMap::new(),
            underlay_ips: BTreeMap::new(),
            created_resources: Vec::new(),
        };
        let residue = mock::MockLeafRunner {
            // Call 9 is the nft probe (0 removal, 1 limit reset, 2 restart,
            // 3..=5 deletions, 6 egress-pin revert): its stdout carries a
            // transit rule.
            stdout_by_match: vec![(
                "nft list ruleset".to_owned(),
                "... comment \"rustynet_substrate_transit\" ...".to_owned(),
            )],
            // Call 8 is `test ! -e`: failing it means the file is STILL there.
            fail_on: vec![8],
            ..MockLeafRunner::default()
        };
        let runners = runner_map(&[("a", &residue)]);
        let err = VxlanSubstrateProvider
            .teardown(&handle, &runners)
            .expect_err("residue must fail the teardown");
        assert!(err.contains("possible residue"), "{err}");
        assert!(err.contains("rustynet_substrate_transit"), "{err}");
        assert!(err.contains("still present"), "{err}");
    }

    /// A guest whose route to the first peer names no device cannot be
    /// attested: setup fails closed with the guest named.
    #[test]
    fn setup_fails_when_the_underlay_cannot_be_derived() {
        use mock::MockLeafRunner;
        let a = MockLeafRunner::default();
        let b = MockLeafRunner::default();
        let runners = runner_map(&[("a", &a), ("b", &b)]);
        let topo = topology(&[("a", "192.168.64.10"), ("b", "192.168.0.30")]);
        let failure = VxlanSubstrateProvider
            .setup(&topo, &runners)
            .expect_err("no route answer, no attestation");
        assert!(
            failure.message.contains("did not name a device"),
            "{}",
            failure.message
        );
        assert!(failure.message.contains("a"), "{}", failure.message);
    }

    /// A failing attestation write fails the setup AFTER the link exists, so
    /// teardown still owns the full residue set.
    #[test]
    fn setup_fails_closed_when_the_attestation_write_fails() {
        use mock::MockLeafRunner;
        let mut a = route_answer_runner();
        a.fail_on = vec![7]; // call 7 = the vm-lab-write-substrate-transit argv (0 del, 1 add, 2 fdb, 3 addr, 4 transit alias, 5 up, 6 route get)
        let b = MockLeafRunner::default();
        let runners = runner_map(&[("a", &a), ("b", &b)]);
        let topo = topology(&[("a", "192.168.64.10"), ("b", "192.168.0.30")]);
        let failure = VxlanSubstrateProvider
            .setup(&topo, &runners)
            .expect_err("a failed write must fail the setup");
        assert!(
            failure.message.contains("vm-lab-write-substrate-transit"),
            "{}",
            failure.message
        );
        assert_eq!(
            failure.partial.created_resources,
            [CreatedResource::link("a", VXLAN_LINK_NAME)]
        );
    }
}
