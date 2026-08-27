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
use std::net::Ipv4Addr;
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
/// Note this is NOT (yet) what `--cross-network-nat-profiles` parses into —
/// that flag keeps its existing shape-only validation so CN-1 changes no
/// behaviour. Tightening the CLI onto this type is a deliberate, separate
/// behavioural change.
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
}

impl Support {
    pub fn is_supported(&self) -> bool {
        matches!(self, Self::Supported)
    }

    /// The documented reason a profile is out of reach, or `None` when it is
    /// supported.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Supported => None,
            Self::UnsupportedByDesign(reason) => Some(reason),
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
}

impl CrossNetworkSubstrateProvider for VxlanSubstrateProvider {
    fn id(&self) -> &'static str {
        "vxlan"
    }

    /// Today this provider builds a FLAT, routable vxlan overlay and applies
    /// no NAT at all: it exists to make cross-LAN peer endpoints routable,
    /// not to shape them. So the only profile it honestly realises is
    /// `baseline_lan`. Every NAT-shaping profile needs the
    /// `apply_nat_profile.sh` semantics ported into
    /// `apply_nat_profile` + `NatModifiers` (CN-4), and `double_nat_cgnat`
    /// additionally needs the two-router chain. Claiming support here would
    /// turn "the profile silently did nothing" into a false pass.
    fn supports(&self, profile: &NatProfileId) -> Support {
        match profile.as_str() {
            "baseline_lan" => Support::Supported,
            "double_nat_cgnat" => Support::UnsupportedByDesign(
                "double_nat_cgnat needs a two-router chain; the vxlan overlay has one router hop \
                 per site"
                    .to_owned(),
            ),
            other => Support::UnsupportedByDesign(format!(
                "{other} needs per-site NAT shaping; the vxlan topology substrate provisions a \
                 flat routable overlay and applies no NAT profile yet (CN-4)"
            )),
        }
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
        // Exact created links when we have them (covers partial setup);
        // otherwise every recorded participant with the well-known link name
        // (covers teardown after a resume where the live handle was rebuilt
        // from the persisted record).
        let targets: Vec<CreatedResource> = if handle.created_resources.is_empty() {
            handle
                .record
                .participants
                .iter()
                .map(|alias| CreatedResource::link(alias, VXLAN_LINK_NAME))
                .collect()
        } else {
            handle.created_resources.clone()
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
            match runner.run(&["sudo", "-n", "ip", "link", "del", &target.name]) {
                Err(err) => errors.push(format!("{}: {err}", target.alias)),
                Ok(output) if !output.success => {
                    // Already-gone is the idempotent success case; anything
                    // else is potential residue and must fail the stage.
                    if !output.stderr.contains("Cannot find device") {
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
            "the slirp substrate is not implemented yet (CN-4); it provisions no overlay",
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
        assert_eq!(a.recorded().len(), 1);
        assert_eq!(b.recorded().len(), 1);
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
            fail_on: vec![0],
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
        // The OTHER node's removal was still attempted (never stop early).
        assert_eq!(ok2.recorded().len(), 1);
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

    /// The vxlan topology substrate provisions a flat routable overlay and
    /// applies no NAT, so it must claim only `baseline_lan` — every shaping
    /// profile is a reasoned `UnsupportedByDesign`, never a silent pass.
    #[test]
    fn vxlan_supports_only_baseline_lan_and_explains_every_refusal() {
        let provider = VxlanSubstrateProvider;
        assert_eq!(
            provider.supports(&NatProfileId::parse("baseline_lan").expect("known")),
            Support::Supported
        );
        assert!(
            provider
                .supports(&NatProfileId::parse("baseline_lan").expect("known"))
                .reason()
                .is_none()
        );
        for shaping in ["full_cone", "port_restricted_cone", "symmetric"] {
            let support = provider.supports(&NatProfileId::parse(shaping).expect("known"));
            assert!(!support.is_supported(), "{shaping} must not be claimed");
            assert!(
                support.reason().expect("reason").contains("no NAT profile"),
                "{shaping} refusal must name the missing NAT shaping"
            );
        }
        let cgnat = provider.supports(&NatProfileId::parse("double_nat_cgnat").expect("known"));
        assert!(!cgnat.is_supported());
        assert!(
            cgnat.reason().expect("reason").contains("two-router chain"),
            "double_nat_cgnat refusal must state the topological reason"
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
