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
/// Canonical overlay pool (LiveLabVmConnectivityRulebook §15.3): addresses are
/// assigned out of per-group /24s inside 172.20.0.0/16, but configured with
/// the /16 mask so every group is on-link across the vxlan mesh.
pub const OVERLAY_PREFIX_LEN: u8 = 16;
/// The whole overlay pool, as the destination prefix a NAT'd site routes
/// through its router namespace.
pub const OVERLAY_POOL_CIDR: &str = "172.20.0.0/16";

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
            gateway_cidr: format!("{gateway_ip}/24"),
            gateway_ip,
            host_cidr: format!("{host_ip}/24"),
            host_ip,
        }
    }
}

impl CrossNetworkSubstrateProvider for VxlanSubstrateProvider {
    fn id(&self) -> &'static str {
        "vxlan"
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
        Self::reset_site_to_flat(runner, alias, &plan.overlay_cidr)
            .map_err(NatApplyError::Failed)?;
        // Anything the previous profile created is gone now, so the recorded
        // resource list must stop naming it.
        handle
            .created_resources
            .retain(|resource| !is_vxlan_nat_resource(resource, alias));
        if profile.as_str() == "baseline_lan" {
            return Ok(());
        }
        Self::build_router_site(runner, handle, alias, &plan, profile, modifiers)
            .map_err(NatApplyError::Failed)
    }

    fn setup(
        &self,
        topology: &SubstrateTopology,
        runners: &BTreeMap<String, &dyn NetLeafRunner>,
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
        for alias in &participants {
            let runner = match Self::runner_for(runners, alias) {
                Ok(runner) => runner,
                Err(err) => return Err(fail(err, handle)),
            };
            let local = handle.underlay_ips[alias].clone();
            let overlay = handle.overlay_ips[alias].clone();
            let mac = overlay_mac(plan.overlay_ips[alias]);
            // Idempotent pre-delete: a leftover device from an aborted run is
            // expected, so a non-zero exit here is fine — but a transport
            // failure is not.
            if let Err(err) = runner.run(&["sudo", "-n", "ip", "link", "del", VXLAN_LINK_NAME]) {
                return Err(fail(format!("{alias}: pre-delete: {err}"), handle));
            }
            if let Err(err) = Self::run_required(
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
                    "nolearning",
                ],
            ) {
                return Err(fail(err, handle));
            }
            handle
                .created_resources
                .push(CreatedResource::link(alias, VXLAN_LINK_NAME));
            for peer in &participants {
                if peer == alias {
                    continue;
                }
                let peer_underlay = handle.underlay_ips[peer].clone();
                if let Err(err) = Self::run_required(
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
                ) {
                    return Err(fail(err, handle));
                }
            }
            let overlay_cidr = format!("{overlay}/{OVERLAY_PREFIX_LEN}");
            if let Err(err) = Self::run_required(
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
            ) {
                return Err(fail(err, handle));
            }
            if let Err(err) = Self::run_required(
                runner,
                alias,
                &["sudo", "-n", "ip", "link", "set", VXLAN_LINK_NAME, "up"],
            ) {
                return Err(fail(err, handle));
            }
        }
        Ok(handle)
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
        let mut errors = Vec::new();
        for target in &targets {
            let runner = match Self::runner_for(runners, &target.alias) {
                Ok(runner) => runner,
                Err(err) => {
                    errors.push(err);
                    continue;
                }
            };
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
        match provider.setup(topology, runners) {
            Ok(handle) => {
                ctx.substrate_record = Some(handle.record.clone());
                ctx.substrate = Some(handle);
                StageOutcome::Passed
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
                    Ok(()) => StageOutcome::Passed,
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
        match plan_overlay(&topology) {
            Err(err) => return StageOutcome::Failed(err),
            Ok(None) => {}
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
            }
        }
        let runners = match build_remote_runners(ctx, "cross_network_substrate_setup") {
            Ok(runners) => runners,
            Err(err) => return StageOutcome::Failed(err),
        };
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
            return StageOutcome::Passed;
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
    }

    impl MockLeafRunner {
        fn scripted_stdout(&self, index: usize, argv: &[&str]) -> String {
            if let Some((_, text)) = self.stdout_for.iter().find(|(at, _)| *at == index) {
                return text.clone();
            }
            let joined = argv.join(" ");
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
        let a = MockLeafRunner::default();
        let b = MockLeafRunner::default();
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
        assert_eq!(td_a.recorded().len(), 1);
        assert_eq!(td_b.recorded().len(), 1);
    }

    /// Invariant (d) at the stage seam: after a PARTIAL setup the context
    /// still carries the created links, and teardown issues a removal per
    /// created interface.
    #[test]
    fn teardown_after_partial_setup_removes_every_created_interface() {
        use mock::MockLeafRunner;
        let mut ctx = empty_ctx();
        // Node "a" provisions; node "b"'s `ip link add` (call 1) fails.
        let a = MockLeafRunner::default();
        let b = MockLeafRunner {
            fail_on: vec![1],
            failure_stderr: "RTNETLINK answers: Operation not permitted".to_owned(),
            ..MockLeafRunner::default()
        };
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
        assert_eq!(
            td_a.recorded(),
            [vec![
                "sudo".to_owned(),
                "-n".to_owned(),
                "ip".to_owned(),
                "link".to_owned(),
                "del".to_owned(),
                VXLAN_LINK_NAME.to_owned()
            ]],
            "one removal per created interface"
        );
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
        use mock::MockLeafRunner;
        let lenovo = MockLeafRunner::default();
        let utm1 = MockLeafRunner::default();
        let utm2 = MockLeafRunner::default();
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
        // Per node: del + add + 2 fdb + addr + up = 6 calls.
        let calls = lenovo.recorded();
        assert_eq!(calls.len(), 6);
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
        assert_eq!(
            calls[5],
            ["sudo", "-n", "ip", "link", "set", VXLAN_LINK_NAME, "up"]
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
    }

    #[test]
    fn vxlan_setup_failure_keeps_partial_created_resources_for_teardown() {
        use mock::MockLeafRunner;
        let lenovo = MockLeafRunner::default();
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
        assert_eq!(
            lenovo_td.recorded(),
            [vec![
                "sudo".to_owned(),
                "-n".to_owned(),
                "ip".to_owned(),
                "link".to_owned(),
                "del".to_owned(),
                VXLAN_LINK_NAME.to_owned()
            ]]
        );
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
        assert_eq!(a.recorded().len(), 3);
        assert_eq!(b.recorded().len(), 3);
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
        let gone = MockLeafRunner {
            fail_on: vec![0, 1, 2],
            failure_stderr: "Cannot find device \"rustynet-vx0\"".to_owned(),
            ..MockLeafRunner::default()
        };
        let ok = MockLeafRunner::default();
        let runners = runner_map(&[("a", &gone), ("b", &ok)]);
        VxlanSubstrateProvider
            .teardown(&handle, &runners)
            .expect("already-deleted must be idempotent success");

        let broken = MockLeafRunner {
            fail_on: vec![0],
            failure_stderr: "RTNETLINK answers: Operation not permitted".to_owned(),
            ..MockLeafRunner::default()
        };
        let ok2 = MockLeafRunner::default();
        let runners = runner_map(&[("a", &broken), ("b", &ok2)]);
        let err = VxlanSubstrateProvider
            .teardown(&handle, &runners)
            .expect_err("real deletion failure must fail the teardown");
        assert!(err.contains("possible residue"), "{err}");
        // The OTHER node's removals were still attempted (never stop early).
        assert_eq!(ok2.recorded().len(), 3);
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
        use mock::MockLeafRunner;
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
            let runner = MockLeafRunner::default();
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
        use mock::MockLeafRunner;
        let runner = MockLeafRunner::default();
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
        assert_eq!(
            handle.created_resources,
            [
                CreatedResource::link("lenovo-1", VXLAN_LINK_NAME),
                CreatedResource::link("utm-1", VXLAN_LINK_NAME),
            ],
            "the removed objects must stop being recorded as created"
        );
    }

    /// Application/removal symmetry: applying a shaping profile with modifiers
    /// and then resetting to `baseline_lan` leaves the recorded resource list
    /// exactly as it started, and re-applying is idempotent rather than
    /// additive.
    #[test]
    fn vxlan_apply_and_reset_are_symmetric_and_idempotent() {
        use mock::MockLeafRunner;
        let runner = MockLeafRunner::default();
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
        use mock::MockLeafRunner;
        let runner = MockLeafRunner::default();
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
        let apply_runner = MockLeafRunner::default();
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
        assert_eq!(
            joined(&lenovo),
            [
                format!("sudo -n ip link del {VXLAN_SITE_LAN_IF}"),
                format!("sudo -n ip netns del {VXLAN_ROUTER_NS}"),
                format!("sudo -n ip link del {VXLAN_LINK_NAME}"),
            ],
            "reverse creation order, and `ip netns del` for the namespace"
        );
        assert_eq!(
            joined(&utm),
            [format!("sudo -n ip link del {VXLAN_LINK_NAME}")]
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
        let a = MockLeafRunner {
            fail_on: vec![0, 1],
            failure_stderr: "Cannot remove namespace file: No such file or directory".to_owned(),
            ..MockLeafRunner::default()
        };
        let runners = runner_map(&[("a", &a)]);
        VxlanSubstrateProvider
            .teardown(&handle, &runners)
            .expect("absent NAT objects are the idempotent success case");
        assert_eq!(
            joined(&a),
            [
                format!("sudo -n ip netns del {VXLAN_ROUTER_NS}"),
                format!("sudo -n ip link del {VXLAN_SITE_LAN_IF}"),
                format!("sudo -n ip link del {VXLAN_LINK_NAME}"),
            ]
        );
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
}
