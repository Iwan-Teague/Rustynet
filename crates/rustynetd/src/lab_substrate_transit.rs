//! LAB-ONLY: the vxlan cross-network substrate transit attestation (AQ-256,
//! design D of `charter/reviews/REVIEW-vxlan-substrate-transit-design-2026-10-03.md`).
//!
//! The live-lab cross-network suite runs the WireGuard dataplane over a vxlan
//! overlay (`rustynet-vx0`, or the `rustynet-vxl` site-LAN veth once a NAT
//! profile applies) whose UDP 4789 encapsulation leaves the guest on its
//! physical underlay. The node killswitch drops that encapsulation in BOTH
//! output base chains (the daemon's `rustynet_g<N>` table and the
//! `rustynet_boot` table installed by ExecStartPre), and full-tunnel policy
//! routing would loop the underlay lookup into the tunnel. The lab
//! orchestrator, which built the topology, attests it in one root-owned file;
//! this module reads and validates that file, and owns the ONE rule builder
//! the runtime emitter, the runtime self-assertion and the boot installer all
//! use.
//!
//! # Why this module cannot reach a release build
//!
//! It is compiled only with the default-OFF cargo feature `lab-substrate`
//! (and only on Linux). Without the feature, the file read, the rule, the
//! route pins, the privileged-helper arm, the status field and the
//! `lab-substrate-capability` subcommand do not exist; an attestation file
//! copied onto a release host is ignored. There is no flag, environment key or
//! unit-file change: in a lab build the attestation's ABSENCE means transit is
//! off and the node behaves byte-identically to a default node.
//!
//! # What an active attestation opens, exactly
//!
//! - in the generation killswitch chain, the existing WireGuard listen-port
//!   allows re-anchored onto the attested overlay (`oifname <overlay> meta
//!   nfproto ipv4 udp dport|sport <wg port> accept`);
//! - in the generation AND boot killswitch chains, one rule per attested peer:
//!   `oifname "<underlay>" ip daddr <peer> udp sport 4789 udp dport 4789
//!   counter accept comment "rustynet_substrate_transit"`. The source-port
//!   match is what bounds it: the vxlan device is created with `srcport 4789
//!   4790`, the kernel vxlan socket holds UDP 4789, and `bind(4789)` fails
//!   with `EADDRINUSE` for every other socket (review experiment A5), so only
//!   the kernel vxlan socket can emit a packet this rule accepts;
//! - one `/32` pin per peer in table 51820 on the underlay, resolved through
//!   the main table, so full-tunnel policy routing cannot loop the
//!   encapsulation into the tunnel (review finding 3).
//!
//! Nothing else: no forward-chain rule, no change to egress derivation, no
//! change to the QH-60 management anchoring.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::io::Read;
use std::net::Ipv4Addr;
use std::path::Path;

/// Fixed path of the orchestrator-written attestation. Absent means transit
/// is off; present but invalid refuses to start.
pub const SUBSTRATE_TRANSIT_ATTESTATION_PATH: &str = "/etc/rustynet/lab/substrate-transit";

/// IANA VXLAN UDP port. The vxlan device is created with `dstport 4789` and
/// `srcport 4789 4790`, so the encapsulation is UDP 4789 -> 4789.
pub const VXLAN_UDP_PORT: u16 = 4789;

/// Comment carried by every transit rule; it is also what the lab's residue
/// assert greps for after teardown.
pub const SUBSTRATE_TRANSIT_COMMENT: &str = "rustynet_substrate_transit";

/// Overlay device the flat vxlan substrate creates (`substrate.rs`
/// `VXLAN_LINK_NAME`). Its link kind must be `vxlan`.
pub const VXLAN_OVERLAY_INTERFACE: &str = "rustynet-vx0";

/// Root-namespace end of the site-LAN veth a NAT profile builds
/// (`substrate.rs` `VXLAN_SITE_LAN_IF`). Its link kind must be `veth`.
pub const SITE_LAN_OVERLAY_INTERFACE: &str = "rustynet-vxl";

/// Upper bound on attested peers; the lab mesh is a handful of guests.
pub const MAX_SUBSTRATE_TRANSIT_PEERS: usize = 32;

/// The exact line `rustynetd lab-substrate-capability` prints. The lab tool
/// treats anything else (including "unknown subcommand") as "capability
/// missing".
pub const LAB_SUBSTRATE_CAPABILITY_LINE: &str = "lab-substrate=yes";

/// Hard cap on the attestation size; a valid file is a few hundred bytes.
const MAX_ATTESTATION_BYTES: u64 = 4096;

/// A validated substrate transit attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubstrateTransit {
    overlay_interface: String,
    underlay_interface: String,
    /// Deduplicated and sorted, so the emitted rule order is deterministic.
    peers: Vec<Ipv4Addr>,
}

impl SubstrateTransit {
    pub fn overlay_interface(&self) -> &str {
        self.overlay_interface.as_str()
    }

    pub fn underlay_interface(&self) -> &str {
        self.underlay_interface.as_str()
    }

    pub fn peers(&self) -> &[Ipv4Addr] {
        self.peers.as_slice()
    }

    /// The daemon status-line field (`rustynet status`).
    pub fn status_field(&self) -> String {
        format!(
            "substrate_transit=lab-active overlay={} underlay={} peers={}",
            self.overlay_interface,
            self.underlay_interface,
            self.peers.len()
        )
    }

    /// The journal WARN the daemon emits once at start while transit is on.
    pub fn journal_line(&self) -> String {
        format!(
            "LAB-ONLY substrate transit ACTIVE (feature lab-substrate): overlay={} underlay={} \
             peers={}",
            self.overlay_interface,
            self.underlay_interface,
            self.peers.len()
        )
    }
}

/// THE transit rule body, shared by the generation-table emitter, the runtime
/// self-assertion (`assert_firewall_ruleset`) and the boot-table installer
/// (AQ-253 pattern: one builder, so the three cannot drift apart).
///
/// Unlike the QH-29 builders in `phase10`, this body carries `counter` itself:
/// the counter is part of the reviewed rule (the live-lab proof reads
/// `counter packets N` > 0 on every transit rule, because conntrack can carry
/// the encapsulation without it, review finding 9), and the exact matcher
/// collapses nft's `counter packets N bytes M` rendering back to `counter`, so
/// the assertion is not coupled to the statistics. The verdict is not the last
/// token (the comment is), which is a second reason no observability token is
/// spliced in by the emitter.
pub fn substrate_transit_allow_tokens(underlay_interface: &str, peer: Ipv4Addr) -> Vec<String> {
    let port = VXLAN_UDP_PORT.to_string();
    vec![
        "oifname".to_owned(),
        underlay_interface.to_owned(),
        "ip".to_owned(),
        "daddr".to_owned(),
        peer.to_string(),
        "udp".to_owned(),
        "sport".to_owned(),
        port.clone(),
        "udp".to_owned(),
        "dport".to_owned(),
        port,
        "counter".to_owned(),
        "accept".to_owned(),
        "comment".to_owned(),
        SUBSTRATE_TRANSIT_COMMENT.to_owned(),
    ]
}

/// Whether `peer` is an address class the attestation may name: RFC 1918
/// private space or RFC 6598 shared (CGNAT) space, never a public address and
/// never unspecified, loopback, multicast or broadcast. The privileged helper
/// re-checks this on the argv (defense in depth).
pub fn is_attestable_transit_peer(peer: Ipv4Addr) -> bool {
    if peer.is_unspecified() || peer.is_loopback() || peer.is_multicast() || peer.is_broadcast() {
        return false;
    }
    let [a, b, _, _] = peer.octets();
    a == 10 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168)
        // 100.64.0.0/10
        || (a == 100 && (64..=127).contains(&b))
}

/// Whether `name` is an acceptable underlay device name: the runtime
/// dataplane's device-name gate, and never a Rustynet-created link (the
/// encapsulation must leave on the physical underlay, not on the tunnel or the
/// overlay itself). The privileged helper re-checks this on the argv.
pub fn is_attestable_underlay_interface(name: &str) -> bool {
    crate::phase10::validate_net_device_name(name).is_ok() && !name.starts_with("rustynet")
}

/// The operator-facing refusal for an invalid attestation (review section C).
pub fn rejected(reason: impl std::fmt::Display) -> String {
    format!(
        "lab substrate transit attestation {SUBSTRATE_TRANSIT_ATTESTATION_PATH} rejected: \
         {reason}; it is written by the lab orchestrator — re-run \
         cross_network_substrate_setup, or delete the file to run without the vxlan substrate"
    )
}

/// Parse the attestation text. Pure: every check that needs no host state.
///
/// Strict format, one `key=value` per line, no comments, no blank lines (a
/// single trailing newline is allowed), no surrounding whitespace, keys in any
/// order: exactly one `version=1`, one `overlay_interface`, one
/// `underlay_interface`, and 1..=32 `peer` lines. An unknown key, a repeated
/// singleton key, or any malformed value refuses. Repeated identical peers are
/// deduplicated.
pub fn parse_attestation(text: &str) -> Result<SubstrateTransit, String> {
    if text.is_empty() {
        return Err("the file is empty".to_owned());
    }
    let body = text.strip_suffix('\n').unwrap_or(text);
    let mut version: Option<&str> = None;
    let mut overlay: Option<&str> = None;
    let mut underlay: Option<&str> = None;
    let mut peer_lines = 0usize;
    let mut peers = BTreeSet::new();
    for (index, line) in body.split('\n').enumerate() {
        let line_number = index + 1;
        if line.is_empty() {
            return Err(format!("line {line_number} is blank"));
        }
        if line.chars().any(|ch| ch.is_whitespace() || ch.is_control()) {
            return Err(format!(
                "line {line_number} contains whitespace or a control character"
            ));
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("line {line_number} is not key=value"));
        };
        if value.is_empty() {
            return Err(format!("line {line_number} has an empty value for {key}"));
        }
        let slot = match key {
            "version" => &mut version,
            "overlay_interface" => &mut overlay,
            "underlay_interface" => &mut underlay,
            "peer" => {
                peer_lines += 1;
                if peer_lines > MAX_SUBSTRATE_TRANSIT_PEERS {
                    return Err(format!(
                        "more than {MAX_SUBSTRATE_TRANSIT_PEERS} peer lines"
                    ));
                }
                peers.insert(parse_peer(value)?);
                continue;
            }
            other => return Err(format!("unknown key {other:?} on line {line_number}")),
        };
        if slot.is_some() {
            return Err(format!("duplicate key {key:?} on line {line_number}"));
        }
        *slot = Some(value);
    }
    match version {
        Some("1") => {}
        Some(other) => return Err(format!("unsupported version {other:?} (expected 1)")),
        None => return Err("missing version=1".to_owned()),
    }
    let overlay = overlay.ok_or_else(|| "missing overlay_interface".to_owned())?;
    if overlay != VXLAN_OVERLAY_INTERFACE && overlay != SITE_LAN_OVERLAY_INTERFACE {
        return Err(format!(
            "overlay_interface {overlay:?} is not one of the lab overlay devices \
             ({VXLAN_OVERLAY_INTERFACE}, {SITE_LAN_OVERLAY_INTERFACE})"
        ));
    }
    let underlay = underlay.ok_or_else(|| "missing underlay_interface".to_owned())?;
    if !is_attestable_underlay_interface(underlay) {
        return Err(format!(
            "underlay_interface {underlay:?} is not a valid physical device name (1-15 chars \
             of [A-Za-z0-9_-], not a rustynet* link)"
        ));
    }
    if peers.is_empty() {
        return Err("no peer lines (at least one is required)".to_owned());
    }
    Ok(SubstrateTransit {
        overlay_interface: overlay.to_owned(),
        underlay_interface: underlay.to_owned(),
        peers: peers.into_iter().collect(),
    })
}

fn parse_peer(value: &str) -> Result<Ipv4Addr, String> {
    let peer = value.parse::<Ipv4Addr>().map_err(|_| {
        format!("peer {value:?} is not a bare IPv4 address (no prefix, no port, no hostname)")
    })?;
    // Canonical spelling only: the address must round-trip byte-for-byte, so
    // the rule the daemon renders is exactly the line the orchestrator wrote.
    if peer.to_string() != value {
        return Err(format!(
            "peer {value:?} is not in canonical dotted-quad form"
        ));
    }
    if !is_attestable_transit_peer(peer) {
        return Err(format!(
            "peer {peer} is outside 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 and \
             100.64.0.0/10 (or is a special-purpose address)"
        ));
    }
    Ok(peer)
}

/// Daemon-side context the attestation is checked against.
#[derive(Debug, Clone, Copy)]
pub struct DaemonTransitContext<'a> {
    /// The RESOLVED egress interface (after `--egress-interface auto`).
    pub egress_interface: &'a str,
    pub blind_exit: bool,
    pub wg_listen_port: u16,
}

/// Host facts the attestation is checked against, gathered by
/// [`HostTransitFacts::collect`] (injected in tests).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostTransitFacts {
    /// Every IPv4 address configured on this host.
    pub local_ipv4: Vec<Ipv4Addr>,
    /// `/sys/class/net/<overlay>` exists.
    pub overlay_present: bool,
    /// `ip -d -o link show dev <overlay>` output; empty when absent.
    pub overlay_link_details: String,
}

impl HostTransitFacts {
    /// Gather the facts for `overlay_interface`. Fails closed: an address
    /// enumeration or link-probe error is an error, never "no facts".
    pub fn collect(overlay_interface: &str) -> Result<Self, String> {
        crate::phase10::validate_net_device_name(overlay_interface)
            .map_err(|message| format!("overlay interface name invalid: {message}"))?;
        let local_ipv4 = local_ipv4_addresses()?;
        let overlay_present = Path::new("/sys/class/net").join(overlay_interface).exists();
        let overlay_link_details = if overlay_present {
            probe_link_details(overlay_interface)?
        } else {
            String::new()
        };
        Ok(Self {
            local_ipv4,
            overlay_present,
            overlay_link_details,
        })
    }
}

fn local_ipv4_addresses() -> Result<Vec<Ipv4Addr>, String> {
    let addresses = nix::ifaddrs::getifaddrs()
        .map_err(|err| format!("local address enumeration failed: {err}"))?;
    Ok(addresses
        .filter_map(|entry| entry.address)
        .filter_map(|address| address.as_sockaddr_in().map(|inet| inet.ip()))
        .collect())
}

/// `ip -d -o link show dev <name>`, argv-only (the name is validated by the
/// caller), read-only and unprivileged.
fn probe_link_details(name: &str) -> Result<String, String> {
    let output = std::process::Command::new("ip")
        .args(["-d", "-o", "link", "show", "dev", name])
        .output()
        .map_err(|err| format!("spawn ip for the overlay link probe failed: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "ip -d -o link show dev {name} exited unsuccessfully: status={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| format!("ip -d -o link show dev {name} returned non-utf8 output"))
}

/// Link kind check on `ip -d -o link show` output: the vxlan overlay renders
/// `vxlan id <vni>`, the site-LAN veth renders the bare `veth` kind token.
fn overlay_link_kind_matches(overlay_interface: &str, details: &str) -> bool {
    let tokens: Vec<&str> = details.split_whitespace().collect();
    match overlay_interface {
        VXLAN_OVERLAY_INTERFACE => tokens.windows(2).any(|window| window == ["vxlan", "id"]),
        SITE_LAN_OVERLAY_INTERFACE => tokens.contains(&"veth"),
        _ => false,
    }
}

/// Every host-fact check, shared by the daemon and the boot check.
pub fn validate_host_facts(
    transit: &SubstrateTransit,
    facts: &HostTransitFacts,
) -> Result<(), String> {
    for peer in &transit.peers {
        if facts.local_ipv4.contains(peer) {
            return Err(rejected(format!("peer {peer} is an address of this host")));
        }
    }
    if !facts.overlay_present {
        return Err(rejected(format!(
            "overlay device {} does not exist",
            transit.overlay_interface
        )));
    }
    if !overlay_link_kind_matches(
        transit.overlay_interface.as_str(),
        &facts.overlay_link_details,
    ) {
        let expected = if transit.overlay_interface == VXLAN_OVERLAY_INTERFACE {
            "vxlan"
        } else {
            "veth"
        };
        return Err(rejected(format!(
            "overlay device {} is not a {expected} link",
            transit.overlay_interface
        )));
    }
    Ok(())
}

/// Every daemon-context check.
pub fn validate_daemon_context(
    transit: &SubstrateTransit,
    context: &DaemonTransitContext<'_>,
) -> Result<(), String> {
    if context.blind_exit {
        return Err(rejected(
            "this node is a blind_exit; the lab substrate transit is never combined with the \
             irreversible blind_exit posture",
        ));
    }
    if context.wg_listen_port == 0 {
        return Err(rejected(
            "wg_listen_port is 0; the overlay WireGuard allows need the real listen port",
        ));
    }
    if transit.underlay_interface != context.egress_interface {
        return Err(format!(
            "lab substrate transit names underlay_interface={} but egress_interface={}; they \
             must be the same physical underlay — the orchestrator sets both; re-run \
             cross_network_substrate_setup",
            transit.underlay_interface, context.egress_interface
        ));
    }
    Ok(())
}

/// Who reads the attestation: the daemon runs as the unprivileged `rustynetd`
/// service user with an empty capability set, while its ExecStartPre boot
/// check runs as root (`PermissionsStartOnly=true` in
/// `scripts/systemd/rustynetd.service`). A root-only (0600) file, or a
/// directory the service user cannot search, is therefore readable by the boot
/// check but not by the daemon, which then refuses to start: say which shape
/// is expected instead of a bare EACCES.
fn permission_hint(err: &std::io::Error) -> &'static str {
    if err.kind() == std::io::ErrorKind::PermissionDenied {
        " (the daemon runs as the rustynetd service user: the file must be root-owned and \
         readable by that user — recommended 0640 root:rustynetd inside /etc/rustynet/lab \
         at 0750 root:rustynetd; 0644 root:root also works)"
    } else {
        ""
    }
}

/// Where the attestation is read from and which uid must own it and its
/// directory. Production is [`AttestationSource::production`] (the fixed path,
/// uid 0); tests inject a temporary path and their own uid so the daemon and
/// boot-check wiring is unit-testable without root.
#[derive(Debug, Clone, Copy)]
pub struct AttestationSource<'a> {
    pub path: &'a Path,
    pub required_uid: u32,
}

impl AttestationSource<'static> {
    pub fn production() -> Self {
        Self {
            path: Path::new(SUBSTRATE_TRANSIT_ATTESTATION_PATH),
            required_uid: 0,
        }
    }
}

/// The attestation's directory must be as trustworthy as the file, the same
/// rule `daemon.rs` `validate_parent_directory_security` applies to key
/// material: a non-symlink directory owned by `required_uid`, not group- or
/// world-writable. Otherwise whoever can write the directory can swap the
/// file between any two checks. `Ok(false)` when the directory does not exist
/// (then the file cannot exist either: transit off).
fn validate_attestation_directory(path: &Path, required_uid: u32) -> Result<bool, String> {
    use std::os::unix::fs::MetadataExt;

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| rejected("the attestation path has no parent directory"))?;
    let meta = match std::fs::symlink_metadata(parent) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => {
            return Err(rejected(format!(
                "cannot inspect the directory {}: {err}{}",
                parent.display(),
                permission_hint(&err)
            )));
        }
    };
    if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
        return Err(rejected(format!(
            "the directory {} is not a non-symlink directory",
            parent.display()
        )));
    }
    if meta.uid() != required_uid {
        return Err(rejected(format!(
            "the directory {} is owned by uid {} (must be uid {required_uid})",
            parent.display(),
            meta.uid()
        )));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(rejected(format!(
            "the directory {} mode {:o} is group- or world-writable",
            parent.display(),
            meta.mode() & 0o7777
        )));
    }
    Ok(true)
}

/// Read the attestation at `path`. `Ok(None)` when it (or its directory) does
/// not exist.
///
/// Fail-closed checks: the directory passes `validate_attestation_directory`;
/// the file is a regular file (never a symlink, also enforced on the open with
/// `O_NOFOLLOW`), opened `O_NONBLOCK` so a FIFO swapped in after the
/// inspection cannot hang daemon start, the inode opened must be the inode
/// inspected, it is owned by `required_uid` (0 in production), not group- or
/// world-writable, at most 4 KiB and valid UTF-8.
pub fn read_attestation_file(path: &Path, required_uid: u32) -> Result<Option<String>, String> {
    if !validate_attestation_directory(path, required_uid)? {
        return Ok(None);
    }
    read_attestation_leaf(path, required_uid, || {})
}

/// The file half of [`read_attestation_file`]. `between_inspection_and_open`
/// is a test seam (production passes a no-op) that lets the tests swap the
/// file between the `lstat` and the `open`, the race the inode identity check
/// and `O_NONBLOCK` exist for.
fn read_attestation_leaf(
    path: &Path,
    required_uid: u32,
    between_inspection_and_open: impl FnOnce(),
) -> Result<Option<String>, String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let link_meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(rejected(format!(
                "cannot inspect the file: {err}{}",
                permission_hint(&err)
            )));
        }
    };
    if link_meta.file_type().is_symlink() {
        return Err(rejected("the file is a symlink"));
    }
    if !link_meta.file_type().is_file() {
        return Err(rejected("the path is not a regular file"));
    }
    between_inspection_and_open();
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits())
        .open(path)
        .map_err(|err| {
            rejected(format!(
                "cannot open the file: {err}{}",
                permission_hint(&err)
            ))
        })?;
    let meta = file
        .metadata()
        .map_err(|err| rejected(format!("cannot inspect the opened file: {err}")))?;
    if !meta.file_type().is_file() {
        return Err(rejected("the opened path is not a regular file"));
    }
    if meta.dev() != link_meta.dev() || meta.ino() != link_meta.ino() {
        return Err(rejected("the file changed between inspection and open"));
    }
    if meta.uid() != required_uid {
        return Err(rejected(format!(
            "the file is owned by uid {} (must be uid {required_uid})",
            meta.uid()
        )));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(rejected(format!(
            "the file mode {:o} is group- or world-writable",
            meta.mode() & 0o7777
        )));
    }
    let mut bytes = Vec::new();
    file.take(MAX_ATTESTATION_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| rejected(format!("cannot read the file: {err}")))?;
    if bytes.len() as u64 > MAX_ATTESTATION_BYTES {
        return Err(rejected(format!(
            "the file is larger than {MAX_ATTESTATION_BYTES} bytes"
        )));
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| rejected("the file is not valid UTF-8"))
}

/// Daemon start: read, parse and validate the production attestation against
/// the resolved daemon config and the host. `Ok(None)` when it is absent.
pub fn load_for_daemon(
    context: &DaemonTransitContext<'_>,
) -> Result<Option<SubstrateTransit>, String> {
    load_for_daemon_from(
        &AttestationSource::production(),
        context,
        HostTransitFacts::collect,
    )
}

/// [`load_for_daemon`] with the source and the host-fact collector injected:
/// file checks, grammar, the daemon context (underlay == resolved egress, not
/// blind_exit, a real WireGuard port) and the host facts, in that order.
pub fn load_for_daemon_from(
    source: &AttestationSource<'_>,
    context: &DaemonTransitContext<'_>,
    collect_facts: impl FnOnce(&str) -> Result<HostTransitFacts, String>,
) -> Result<Option<SubstrateTransit>, String> {
    let Some(text) = read_attestation_file(source.path, source.required_uid)? else {
        return Ok(None);
    };
    let transit = parse_attestation(text.as_str()).map_err(rejected)?;
    validate_daemon_context(&transit, context)?;
    let facts = collect_facts(transit.overlay_interface())?;
    validate_host_facts(&transit, &facts)?;
    Ok(Some(transit))
}

/// `linux-killswitch-boot-check` (root, ExecStartPre): the same file, format
/// and host checks, run before the boot check execs anything. The boot check
/// has no resolved egress interface or node role (the unit's ExecStartPre does
/// not pass them); the daemon re-checks both before it emits anything, and
/// refuses to start on a mismatch. The boot installer additionally requires
/// `--wg-listen-port` (see
/// `linux_killswitch_boot::install_linux_boot_killswitch_with_substrate_transit`).
pub fn load_for_boot_check() -> Result<Option<SubstrateTransit>, String> {
    load_for_boot_check_from(&AttestationSource::production(), HostTransitFacts::collect)
}

/// [`load_for_boot_check`] with the source and the host-fact collector
/// injected.
pub fn load_for_boot_check_from(
    source: &AttestationSource<'_>,
    collect_facts: impl FnOnce(&str) -> Result<HostTransitFacts, String>,
) -> Result<Option<SubstrateTransit>, String> {
    let Some(text) = read_attestation_file(source.path, source.required_uid)? else {
        return Ok(None);
    };
    let transit = parse_attestation(text.as_str()).map_err(rejected)?;
    let facts = collect_facts(transit.overlay_interface())?;
    validate_host_facts(&transit, &facts)?;
    Ok(Some(transit))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    const VALID: &str = "version=1\noverlay_interface=rustynet-vx0\nunderlay_interface=eth0\n\
                         peer=192.168.122.31\npeer=192.168.0.32\n";

    fn valid() -> SubstrateTransit {
        parse_attestation(VALID).expect("valid attestation must parse")
    }

    fn vxlan_facts() -> HostTransitFacts {
        HostTransitFacts {
            local_ipv4: vec![Ipv4Addr::new(192, 168, 0, 30), Ipv4Addr::LOCALHOST],
            overlay_present: true,
            overlay_link_details: "7: rustynet-vx0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 \
                 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\\    link/ether \
                 aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff promiscuity 0 allmulti 0 minmtu 68 \
                 maxmtu 65535 \\    vxlan id 4242 dev eth0 srcport 4789 4790 dstport 4789 \
                 nolearning ttl auto ageing 300"
                .to_owned(),
        }
    }

    fn daemon_context(egress: &str) -> DaemonTransitContext<'_> {
        DaemonTransitContext {
            egress_interface: egress,
            blind_exit: false,
            wg_listen_port: 51820,
        }
    }

    #[test]
    fn lab_substrate_transit_parse_accepts_the_contract_format() {
        let transit = valid();
        assert_eq!(transit.overlay_interface(), "rustynet-vx0");
        assert_eq!(transit.underlay_interface(), "eth0");
        assert_eq!(
            transit.peers(),
            &[
                Ipv4Addr::new(192, 168, 0, 32),
                Ipv4Addr::new(192, 168, 122, 31)
            ]
        );
        assert_eq!(
            transit.status_field(),
            "substrate_transit=lab-active overlay=rustynet-vx0 underlay=eth0 peers=2"
        );
        assert_eq!(
            transit.journal_line(),
            "LAB-ONLY substrate transit ACTIVE (feature lab-substrate): overlay=rustynet-vx0 \
             underlay=eth0 peers=2"
        );
        // No trailing newline, keys in another order, the veth overlay, a
        // CGNAT and a 10/8 peer, and a duplicated peer that deduplicates.
        let transit = parse_attestation(
            "peer=100.64.0.9\nunderlay_interface=enp0s9\noverlay_interface=rustynet-vxl\n\
             version=1\npeer=10.1.2.3\npeer=100.64.0.9",
        )
        .expect("reordered attestation must parse");
        assert_eq!(transit.overlay_interface(), "rustynet-vxl");
        assert_eq!(transit.peers().len(), 2);
    }

    fn assert_refused(text: &str, needle: &str) {
        let err = parse_attestation(text).expect_err("attestation must be refused");
        assert!(err.contains(needle), "expected {needle:?} in {err:?}");
    }

    #[test]
    fn lab_substrate_transit_parse_refuses_unknown_key() {
        assert_refused(&format!("{VALID}mtu=1450\n"), "unknown key");
        assert_refused(&format!("{VALID}#comment\n"), "not key=value");
    }

    #[test]
    fn lab_substrate_transit_parse_refuses_duplicate_key() {
        assert_refused(&format!("{VALID}version=1\n"), "duplicate key");
        assert_refused(
            &format!("{VALID}overlay_interface=rustynet-vx0\n"),
            "duplicate key",
        );
        assert_refused(
            &format!("{VALID}underlay_interface=eth0\n"),
            "duplicate key",
        );
    }

    #[test]
    fn lab_substrate_transit_parse_refuses_cidr_peer() {
        let base = "version=1\noverlay_interface=rustynet-vx0\nunderlay_interface=eth0\n";
        for bad in [
            "192.168.122.0/24",
            "192.168.122.31/32",
            "192.168.122.31:4789",
            "lab-exit",
            "192.168.122.031",
            "fd00::1",
        ] {
            assert_refused(&format!("{base}peer={bad}\n"), "peer");
        }
    }

    #[test]
    fn lab_substrate_transit_parse_refuses_public_peer() {
        let base = "version=1\noverlay_interface=rustynet-vx0\nunderlay_interface=eth0\n";
        for bad in [
            "8.8.8.8",
            "172.32.0.1",
            "100.128.0.1",
            "127.0.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "169.254.1.1",
        ] {
            assert_refused(&format!("{base}peer={bad}\n"), "outside");
        }
    }

    #[test]
    fn lab_substrate_transit_parse_refuses_own_address_peer() {
        let transit = valid();
        let mut facts = vxlan_facts();
        validate_host_facts(&transit, &facts).expect("foreign peers must pass");
        facts.local_ipv4.push(Ipv4Addr::new(192, 168, 122, 31));
        let err = validate_host_facts(&transit, &facts).expect_err("own address must refuse");
        assert!(err.contains("is an address of this host"), "{err}");
        assert!(
            err.contains("re-run cross_network_substrate_setup"),
            "{err}"
        );
    }

    #[test]
    fn lab_substrate_transit_parse_refuses_zero_peers() {
        assert_refused(
            "version=1\noverlay_interface=rustynet-vx0\nunderlay_interface=eth0\n",
            "no peer lines",
        );
    }

    #[test]
    fn lab_substrate_transit_parse_refuses_too_many_peers() {
        let mut text =
            String::from("version=1\noverlay_interface=rustynet-vx0\nunderlay_interface=eth0\n");
        for index in 0..=MAX_SUBSTRATE_TRANSIT_PEERS {
            text.push_str(&format!("peer=10.0.0.{}\n", index + 1));
        }
        assert_refused(&text, "more than 32 peer lines");
        // Exactly 32 is accepted.
        let mut text =
            String::from("version=1\noverlay_interface=rustynet-vx0\nunderlay_interface=eth0\n");
        for index in 0..MAX_SUBSTRATE_TRANSIT_PEERS {
            text.push_str(&format!("peer=10.0.0.{}\n", index + 1));
        }
        assert_eq!(
            parse_attestation(&text).expect("32 peers").peers().len(),
            32
        );
    }

    #[test]
    fn lab_substrate_transit_parse_refuses_unlisted_overlay() {
        for bad in ["rustynet0", "rustynet-vx1", "eth1", "vxlan0"] {
            assert_refused(
                &format!(
                    "version=1\noverlay_interface={bad}\nunderlay_interface=eth0\n\
                     peer=10.0.0.2\n"
                ),
                "not one of the lab overlay devices",
            );
        }
    }

    #[test]
    fn lab_substrate_transit_parse_refuses_rustynet_underlay() {
        for bad in [
            "rustynet0",
            "rustynet-vx0",
            "rustynet-vxl",
            "eth0;drop",
            "a-very-long-name0",
        ] {
            assert_refused(
                &format!(
                    "version=1\noverlay_interface=rustynet-vx0\nunderlay_interface={bad}\n\
                     peer=10.0.0.2\n"
                ),
                "underlay_interface",
            );
        }
    }

    #[test]
    fn lab_substrate_transit_parse_refuses_empty_file() {
        assert_refused("", "empty");
        assert_refused("\n", "blank");
        assert_refused(&format!("version=1\n\n{}", &VALID[10..]), "blank");
        assert_refused(&VALID.replace('\n', "\r\n"), "whitespace or a control");
        assert_refused(&VALID.replace("eth0", " eth0"), "whitespace");
        assert_refused(
            &VALID.replace("version=1", "version=2"),
            "unsupported version",
        );
        assert_refused(&VALID.replace("version=1\n", ""), "missing version");
        assert_refused(&VALID.replace("peer=192.168.0.32", "peer="), "empty value");
    }

    fn write_file(dir: &Path, name: &str, body: &str, mode: u32) -> std::path::PathBuf {
        let path = dir.join(name);
        let mut file = std::fs::File::create(&path).expect("create");
        file.write_all(body.as_bytes()).expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
        path
    }

    fn current_uid() -> u32 {
        nix::unistd::getuid().as_raw()
    }

    #[test]
    fn lab_substrate_transit_read_accepts_a_private_file_and_absence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_file(dir.path(), "substrate-transit", VALID, 0o600);
        let text = read_attestation_file(&path, current_uid())
            .expect("a private file must read")
            .expect("present");
        assert_eq!(text, VALID);
        // 0644 is fine: only group/world WRITE is refused.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        read_attestation_file(&path, current_uid()).expect("0644 must read");
        assert_eq!(
            read_attestation_file(&dir.path().join("absent"), current_uid())
                .expect("absence is not an error"),
            None
        );
    }

    #[test]
    fn lab_substrate_transit_parse_refuses_symlink() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = write_file(dir.path(), "real", VALID, 0o600);
        let link = dir.path().join("substrate-transit");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        let err = read_attestation_file(&link, current_uid()).expect_err("symlink must refuse");
        assert!(err.contains("symlink"), "{err}");
        // A directory in the file's place (its parent is the trusted tempdir).
        let subdir = dir.path().join("subdir");
        std::fs::create_dir(&subdir).expect("mkdir");
        let err =
            read_attestation_file(&subdir, current_uid()).expect_err("a directory must refuse");
        assert!(err.contains("not a regular file"), "{err}");
    }

    #[test]
    fn lab_substrate_transit_parse_refuses_group_writable() {
        let dir = tempfile::tempdir().expect("tempdir");
        for mode in [0o620, 0o602, 0o666] {
            let path = write_file(dir.path(), "substrate-transit", VALID, mode);
            let err = read_attestation_file(&path, current_uid())
                .expect_err("group/world-writable must refuse");
            assert!(err.contains("writable"), "{mode:o}: {err}");
        }
    }

    #[test]
    fn lab_substrate_transit_parse_refuses_non_root_owner() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_file(dir.path(), "substrate-transit", VALID, 0o600);
        let other_uid = current_uid().wrapping_add(1);
        // The file itself (the directory check is exercised separately: an
        // unprivileged test cannot give the file and its directory different
        // owners).
        let err = read_attestation_leaf(&path, other_uid, || {})
            .expect_err("wrong file owner must refuse");
        assert!(err.contains("the file is owned by uid"), "{err}");
        // And through the full reader the directory refuses first.
        let err = read_attestation_file(&path, other_uid).expect_err("wrong owner must refuse");
        assert!(err.contains("is owned by uid"), "{err}");
        let big = write_file(dir.path(), "big", &"x".repeat(5000), 0o600);
        let err = read_attestation_file(&big, current_uid()).expect_err("oversize must refuse");
        assert!(err.contains("larger than"), "{err}");
    }

    /// The directory is held to the same rule as the file (review finding
    /// 6): a non-symlink directory owned by the required uid, not group- or
    /// world-writable; an absent directory means transit off.
    #[test]
    fn lab_substrate_transit_refuses_an_untrustworthy_directory() {
        let root = tempfile::tempdir().expect("tempdir");
        let lab = root.path().join("lab");
        std::fs::create_dir(&lab).expect("mkdir");
        std::fs::set_permissions(&lab, std::fs::Permissions::from_mode(0o750)).expect("chmod");
        let path = write_file(&lab, "substrate-transit", VALID, 0o640);
        read_attestation_file(&path, current_uid())
            .expect("a 0750 directory and a 0640 file must read")
            .expect("present");
        for mode in [0o770, 0o757, 0o777] {
            std::fs::set_permissions(&lab, std::fs::Permissions::from_mode(mode)).expect("chmod");
            let err = read_attestation_file(&path, current_uid())
                .expect_err("a writable directory must refuse");
            assert!(err.contains("group- or world-writable"), "{mode:o}: {err}");
            assert!(err.contains("the directory"), "{mode:o}: {err}");
        }
        std::fs::set_permissions(&lab, std::fs::Permissions::from_mode(0o750)).expect("chmod");
        let err = read_attestation_file(&path, current_uid().wrapping_add(1))
            .expect_err("a foreign-owned directory must refuse");
        assert!(err.contains("the directory"), "{err}");
        assert!(err.contains("is owned by uid"), "{err}");
        // A symlinked directory refuses even though its target is fine.
        let link = root.path().join("lablink");
        std::os::unix::fs::symlink(&lab, &link).expect("symlink");
        let err = read_attestation_file(&link.join("substrate-transit"), current_uid())
            .expect_err("a symlinked directory must refuse");
        assert!(err.contains("not a non-symlink directory"), "{err}");
        // A regular file in the directory's place refuses.
        let err = read_attestation_file(&path.join("substrate-transit"), current_uid())
            .expect_err("a file as the directory must refuse");
        assert!(err.contains("not a non-symlink directory"), "{err}");
        // An absent directory is transit off.
        assert_eq!(
            read_attestation_file(&root.path().join("absent/substrate-transit"), current_uid())
                .expect("an absent directory is not an error"),
            None
        );
    }

    /// The inode opened must be the inode inspected (review mutant A9): a file
    /// renamed over the path between the `lstat` and the `open` — same owner,
    /// same mode, valid content — is refused.
    #[test]
    fn lab_substrate_transit_refuses_a_file_swapped_between_inspection_and_open() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_file(dir.path(), "substrate-transit", VALID, 0o600);
        let swapped = VALID.replace("peer=192.168.0.32", "peer=10.9.9.9");
        let replacement = write_file(dir.path(), "replacement", &swapped, 0o600);
        let err = read_attestation_leaf(&path, current_uid(), || {
            std::fs::rename(&replacement, &path).expect("rename over the attestation");
        })
        .expect_err("a swapped inode must refuse");
        assert!(err.contains("changed between inspection and open"), "{err}");
        // Without a swap the same call reads the file.
        let text = read_attestation_leaf(&path, current_uid(), || {})
            .expect("unswapped read")
            .expect("present");
        assert_eq!(text, swapped);
    }

    /// A FIFO swapped in after the inspection must not hang daemon start
    /// (`O_NONBLOCK`): the read returns an error promptly.
    #[test]
    fn lab_substrate_transit_fifo_swap_cannot_hang_start() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_file(dir.path(), "substrate-transit", VALID, 0o600);
        let (done, finished) = std::sync::mpsc::channel();
        let racing_path = path.clone();
        std::thread::spawn(move || {
            let result = read_attestation_leaf(&racing_path, current_uid(), || {
                std::fs::remove_file(&racing_path).expect("unlink");
                nix::unistd::mkfifo(
                    &racing_path,
                    nix::sys::stat::Mode::from_bits_truncate(0o600),
                )
                .expect("mkfifo");
            });
            let _ = done.send(result);
        });
        let result = finished
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the read must not block on a swapped-in FIFO");
        let err = result.expect_err("a FIFO must refuse");
        assert!(
            err.contains("not a regular file") || err.contains("changed"),
            "{err}"
        );
    }

    /// The daemon runs as an unprivileged service user: an unreadable
    /// attestation refuses to start, naming the expected file shape.
    #[test]
    fn lab_substrate_transit_unreadable_file_names_the_expected_shape() {
        if nix::unistd::geteuid().is_root() {
            return; // root reads a 0200 file; the shape is only observable unprivileged
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_file(dir.path(), "substrate-transit", VALID, 0o200);
        let err = read_attestation_file(&path, current_uid()).expect_err("unreadable refuses");
        assert!(err.contains("0640 root:rustynetd"), "{err}");
        assert!(
            err.contains("re-run cross_network_substrate_setup"),
            "{err}"
        );
    }

    #[test]
    fn lab_substrate_transit_requires_underlay_equal_egress() {
        let transit = valid();
        validate_daemon_context(&transit, &daemon_context("eth0")).expect("equal must pass");
        let err = validate_daemon_context(&transit, &daemon_context("rustynet-vx0"))
            .expect_err("mismatch must refuse");
        assert_eq!(
            err,
            "lab substrate transit names underlay_interface=eth0 but \
             egress_interface=rustynet-vx0; they must be the same physical underlay — the \
             orchestrator sets both; re-run cross_network_substrate_setup"
        );
    }

    #[test]
    fn lab_substrate_transit_refused_on_blind_exit() {
        let transit = valid();
        let mut context = daemon_context("eth0");
        context.blind_exit = true;
        let err = validate_daemon_context(&transit, &context).expect_err("blind_exit refuses");
        assert!(err.contains("blind_exit"), "{err}");
        let mut context = daemon_context("eth0");
        context.wg_listen_port = 0;
        let err = validate_daemon_context(&transit, &context).expect_err("port 0 refuses");
        assert!(err.contains("wg_listen_port is 0"), "{err}");
    }

    #[test]
    fn lab_substrate_transit_overlay_must_exist_with_the_right_kind() {
        let transit = valid();
        let mut facts = vxlan_facts();
        facts.overlay_present = false;
        let err = validate_host_facts(&transit, &facts).expect_err("absent overlay refuses");
        assert!(err.contains("does not exist"), "{err}");
        let mut facts = vxlan_facts();
        facts.overlay_link_details =
            "7: rustynet-vx0: <UP> mtu 1500 \\    veth addrgenmode eui64".to_owned();
        let err = validate_host_facts(&transit, &facts).expect_err("wrong kind refuses");
        assert!(err.contains("is not a vxlan link"), "{err}");
        // The veth overlay needs the veth kind, and the vxlan kind is refused.
        let veth = parse_attestation(&VALID.replace("rustynet-vx0", "rustynet-vxl"))
            .expect("veth overlay parses");
        let err = validate_host_facts(&veth, &vxlan_facts()).expect_err("vxlan is not veth");
        assert!(err.contains("is not a veth link"), "{err}");
        let mut facts = vxlan_facts();
        facts.overlay_link_details = "8: rustynet-vxl@if2: <UP> mtu 1500 \\    link/ether \
             aa:bb:cc:dd:ee:01 link-netns rustynet-vxr promiscuity 0 \\    veth addrgenmode eui64"
            .to_owned();
        validate_host_facts(&veth, &facts).expect("veth overlay with the veth kind passes");
    }

    fn temp_source(dir: &Path, body: &str) -> std::path::PathBuf {
        write_file(dir, "substrate-transit", body, 0o640)
    }

    /// The boot check's wiring (review mutant A10): it applies the host facts
    /// of the attested overlay — an absent overlay, a wrong link kind, a peer
    /// that is this host, or a failing fact collection all refuse — and an
    /// absent attestation is transit off.
    #[test]
    fn boot_check_loader_applies_the_host_facts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let absent = dir.path().join("absent");
        let source = AttestationSource {
            path: &absent,
            required_uid: current_uid(),
        };
        let loaded = load_for_boot_check_from(&source, |_| panic!("no facts when absent"))
            .expect("absent is not an error");
        assert_eq!(loaded, None);

        let path = temp_source(dir.path(), VALID);
        let source = AttestationSource {
            path: &path,
            required_uid: current_uid(),
        };
        let loaded = load_for_boot_check_from(&source, |overlay| {
            assert_eq!(overlay, "rustynet-vx0");
            Ok(vxlan_facts())
        })
        .expect("valid attestation with good facts")
        .expect("present");
        assert_eq!(loaded, valid());

        let mut absent_overlay = vxlan_facts();
        absent_overlay.overlay_present = false;
        let err = load_for_boot_check_from(&source, |_| Ok(absent_overlay))
            .expect_err("an absent overlay must refuse");
        assert!(err.contains("does not exist"), "{err}");

        let mut own_peer = vxlan_facts();
        own_peer.local_ipv4.push(Ipv4Addr::new(192, 168, 122, 31));
        let err = load_for_boot_check_from(&source, |_| Ok(own_peer))
            .expect_err("an own-address peer must refuse");
        assert!(err.contains("address of this host"), "{err}");

        let mut wrong_kind = vxlan_facts();
        wrong_kind.overlay_link_details = "7: rustynet-vx0: <UP> \\    dummy".to_owned();
        let err = load_for_boot_check_from(&source, |_| Ok(wrong_kind))
            .expect_err("a wrong link kind must refuse");
        assert!(err.contains("is not a vxlan link"), "{err}");

        let err = load_for_boot_check_from(&source, |_| Err("probe failed".to_owned()))
            .expect_err("a failed fact collection must refuse");
        assert_eq!(err, "probe failed");

        // A malformed attestation refuses with the operator-facing text.
        let bad = write_file(dir.path(), "bad", "version=1\n", 0o640);
        let source = AttestationSource {
            path: &bad,
            required_uid: current_uid(),
        };
        let err = load_for_boot_check_from(&source, |_| Ok(vxlan_facts()))
            .expect_err("malformed refuses");
        assert!(
            err.contains("re-run cross_network_substrate_setup"),
            "{err}"
        );
    }

    /// The daemon loader's wiring: context checks (resolved egress, role, wg
    /// port) and host facts both apply, in that order.
    #[test]
    fn daemon_loader_applies_context_and_host_facts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = temp_source(dir.path(), VALID);
        let source = AttestationSource {
            path: &path,
            required_uid: current_uid(),
        };
        let loaded = load_for_daemon_from(&source, &daemon_context("eth0"), |_| Ok(vxlan_facts()))
            .expect("valid")
            .expect("present");
        assert_eq!(loaded, valid());

        let err = load_for_daemon_from(&source, &daemon_context("enp0s9"), |_| Ok(vxlan_facts()))
            .expect_err("egress mismatch refuses");
        assert!(err.contains("egress_interface=enp0s9"), "{err}");

        let mut blind = daemon_context("eth0");
        blind.blind_exit = true;
        let err = load_for_daemon_from(&source, &blind, |_| Ok(vxlan_facts()))
            .expect_err("blind_exit refuses");
        assert!(err.contains("blind_exit"), "{err}");

        let mut facts = vxlan_facts();
        facts.overlay_present = false;
        let err = load_for_daemon_from(&source, &daemon_context("eth0"), |_| Ok(facts))
            .expect_err("host facts apply");
        assert!(err.contains("does not exist"), "{err}");
    }

    #[test]
    fn substrate_transit_rule_tokens_render_the_contract_rule() {
        assert_eq!(
            substrate_transit_allow_tokens("eth0", Ipv4Addr::new(192, 168, 122, 31)).join(" "),
            "oifname eth0 ip daddr 192.168.122.31 udp sport 4789 udp dport 4789 counter accept \
             comment rustynet_substrate_transit"
        );
    }

    #[test]
    fn attestable_peer_class_boundaries() {
        for good in [
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.0.1",
            "100.64.0.1",
        ] {
            assert!(
                is_attestable_transit_peer(good.parse().expect("ip")),
                "{good}"
            );
        }
        for bad in [
            "9.255.255.255",
            "11.0.0.1",
            "172.15.0.1",
            "172.32.0.1",
            "192.169.0.1",
        ] {
            assert!(
                !is_attestable_transit_peer(bad.parse().expect("ip")),
                "{bad}"
            );
        }
        assert!(!is_attestable_transit_peer(Ipv4Addr::new(
            100, 63, 255, 255
        )));
        assert!(is_attestable_transit_peer(Ipv4Addr::new(
            100, 127, 255, 254
        )));
        assert!(!is_attestable_transit_peer(Ipv4Addr::new(100, 128, 0, 0)));
    }

    // ── Linux netns witness (review Experiments table) ─────────────────────
    //
    // `#[ignore]`: needs root, `ip`, `nft` and `python3`. Run on a Linux lab
    // box only, e.g.
    //   sudo -n <rustynetd lib test binary> --ignored --exact \
    //     lab_substrate_transit::tests::netns_witness_design_d
    // Everything happens inside three throwaway network namespaces
    // (`rn_impl_<pid>_{h,g,p}`, deleted afterwards, also on failure): no
    // host-namespace device, table, rule or route is touched. Topology: H
    // plays the guest root namespace (both killswitch tables, full-tunnel
    // table 51820), G a forwarding gateway, P the peer guest; the peer's
    // underlay is OFF-LINK behind G, the vxlan device is created exactly the
    // way `substrate.rs` creates it (`local`, no `dev`) plus the contract's
    // `srcport 4789 4790`. The killswitch tables use throwaway names; their
    // transit rules come from the REAL shared builders.

    struct Netns {
        h: String,
        g: String,
        p: String,
    }

    impl Drop for Netns {
        fn drop(&mut self) {
            for ns in [&self.h, &self.g, &self.p] {
                let _ = std::process::Command::new("ip")
                    .args(["netns", "del", ns.as_str()])
                    .output();
            }
        }
    }

    fn cmd(args: &[&str]) -> std::process::Output {
        std::process::Command::new(args[0])
            .args(&args[1..])
            .output()
            .unwrap_or_else(|err| panic!("spawn {args:?}: {err}"))
    }

    fn must(args: &[&str]) -> String {
        let output = cmd(args);
        assert!(
            output.status.success(),
            "{args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    fn in_ns(ns: &str, args: &[&str]) -> Vec<String> {
        let mut argv = vec![
            "ip".to_owned(),
            "netns".to_owned(),
            "exec".to_owned(),
            ns.to_owned(),
        ];
        argv.extend(args.iter().map(|arg| (*arg).to_owned()));
        argv
    }

    fn must_ns(ns: &str, args: &[&str]) -> String {
        let argv = in_ns(ns, args);
        let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
        must(&refs)
    }

    const UNDERLAY: &str = "ua";
    const H_UNDERLAY_IP: &str = "10.99.0.1";
    const GATEWAY_IP: &str = "10.99.0.254";
    const PEER_UNDERLAY_IP: &str = "10.98.0.2";
    const WG_PORT: &str = "51820";

    #[derive(Clone, Copy)]
    struct Shape {
        srcport_pinned: bool,
        gen_transit: bool,
        boot_transit: bool,
        killswitch: bool,
        pin: bool,
    }

    const DESIGN_D: Shape = Shape {
        srcport_pinned: true,
        gen_transit: true,
        boot_transit: true,
        killswitch: true,
        pin: true,
    };

    fn build(tag: &str, shape: Shape) -> Netns {
        let netns = Netns {
            h: format!("{tag}_h"),
            g: format!("{tag}_g"),
            p: format!("{tag}_p"),
        };
        for ns in [&netns.h, &netns.g, &netns.p] {
            must(&["ip", "netns", "add", ns.as_str()]);
            must(&["ip", "-n", ns.as_str(), "link", "set", "lo", "up"]);
        }
        // IPv6 off, as the daemon hard-disables it: otherwise the overlay's
        // own IPv6 chatter from P seeds conntrack in H and the established
        // accept carries the encapsulation with no transit rule at all
        // (review experiment D3), which would make every negative vacuous.
        for ns in [&netns.h, &netns.p] {
            must_ns(
                ns,
                &[
                    "sysctl",
                    "-qw",
                    "net.ipv6.conf.all.disable_ipv6=1",
                    "net.ipv6.conf.default.disable_ipv6=1",
                ],
            );
        }
        let (h, g, p) = (netns.h.as_str(), netns.g.as_str(), netns.p.as_str());
        must(&[
            "ip", "-n", h, "link", "add", UNDERLAY, "type", "veth", "peer", "name", "gh", "netns",
            g,
        ]);
        must(&[
            "ip", "-n", p, "link", "add", "pa", "type", "veth", "peer", "name", "gp", "netns", g,
        ]);
        must(&[
            "ip",
            "-n",
            h,
            "addr",
            "add",
            "10.99.0.1/24",
            "dev",
            UNDERLAY,
        ]);
        must(&["ip", "-n", g, "addr", "add", "10.99.0.254/24", "dev", "gh"]);
        must(&["ip", "-n", g, "addr", "add", "10.98.0.254/24", "dev", "gp"]);
        must(&["ip", "-n", p, "addr", "add", "10.98.0.2/24", "dev", "pa"]);
        for (ns, dev) in [(h, UNDERLAY), (g, "gh"), (g, "gp"), (p, "pa")] {
            must(&["ip", "-n", ns, "link", "set", dev, "up"]);
        }
        must_ns(g, &["sysctl", "-qw", "net.ipv4.ip_forward=1"]);
        must(&["ip", "-n", h, "route", "add", "default", "via", GATEWAY_IP]);
        must(&[
            "ip",
            "-n",
            p,
            "route",
            "add",
            "default",
            "via",
            "10.98.0.254",
        ]);
        for (ns, local, remote, overlay) in [
            (h, H_UNDERLAY_IP, PEER_UNDERLAY_IP, "172.31.0.1/24"),
            (p, PEER_UNDERLAY_IP, H_UNDERLAY_IP, "172.31.0.2/24"),
        ] {
            let mut argv = vec![
                "ip",
                "-n",
                ns,
                "link",
                "add",
                "rustynet-vx0",
                "type",
                "vxlan",
                "id",
                "4242",
                "local",
                local,
                "dstport",
                "4789",
            ];
            if shape.srcport_pinned {
                argv.extend(["srcport", "4789", "4790"]);
            }
            argv.push("nolearning");
            must(&argv);
            must(&[
                "bridge",
                "-n",
                ns,
                "fdb",
                "append",
                "00:00:00:00:00:00",
                "dev",
                "rustynet-vx0",
                "dst",
                remote,
            ]);
            must(&[
                "ip",
                "-n",
                ns,
                "addr",
                "add",
                overlay,
                "dev",
                "rustynet-vx0",
            ]);
            must(&["ip", "-n", ns, "link", "set", "rustynet-vx0", "up"]);
        }
        // Full tunnel in H: every lookup goes to table 51820 whose default is
        // a stand-in tunnel device (review experiment R).
        must(&["ip", "-n", h, "link", "add", "rnwg0", "type", "dummy"]);
        must(&["ip", "-n", h, "link", "set", "rnwg0", "up"]);
        must(&[
            "ip", "-n", h, "route", "add", "default", "dev", "rnwg0", "table", "51820",
        ]);
        must(&[
            "ip",
            "-n",
            h,
            "route",
            "add",
            "10.99.0.0/24",
            "dev",
            UNDERLAY,
            "table",
            "51820",
        ]);
        // The WireGuard peer-endpoint pin the daemon already installs,
        // route-derived onto the overlay (review finding 6).
        must(&[
            "ip",
            "-n",
            h,
            "route",
            "add",
            "172.31.0.2/32",
            "dev",
            "rustynet-vx0",
            "table",
            "51820",
        ]);
        must(&[
            "ip", "-n", h, "rule", "add", "priority", "32765", "table", "51820",
        ]);
        if shape.pin {
            must(&[
                "ip",
                "-n",
                h,
                "route",
                "replace",
                "10.98.0.2/32",
                "via",
                GATEWAY_IP,
                "dev",
                UNDERLAY,
                "table",
                "51820",
            ]);
        }
        if shape.killswitch {
            install_tables(h, tag, shape);
        }
        netns
    }

    fn nft_ns(ns: &str, args: &[&str]) {
        let mut argv = vec!["nft"];
        argv.extend_from_slice(args);
        must_ns(ns, &argv);
    }

    fn install_tables(h: &str, tag: &str, shape: Shape) {
        let transit = parse_attestation(&format!(
            "version=1\noverlay_interface=rustynet-vx0\nunderlay_interface={UNDERLAY}\n\
             peer={PEER_UNDERLAY_IP}\n"
        ))
        .expect("witness attestation parses");
        let generation = format!("{tag}_gen");
        let boot = format!("{tag}_boot");
        let base_chain = |table: &str| {
            nft_ns(h, &["add", "table", "inet", table]);
            nft_ns(
                h,
                &[
                    "add",
                    "chain",
                    "inet",
                    table,
                    "killswitch",
                    "{",
                    "type",
                    "filter",
                    "hook",
                    "output",
                    "priority",
                    "0",
                    ";",
                    "policy",
                    "drop",
                    ";",
                    "}",
                ],
            );
            nft_ns(
                h,
                &[
                    "add",
                    "rule",
                    "inet",
                    table,
                    "killswitch",
                    "oifname",
                    "lo",
                    "accept",
                ],
            );
        };
        let established = |table: &str| {
            for body in crate::phase10::LinuxCommandSystem::established_related_accept_tokens() {
                let mut argv = vec!["add", "rule", "inet", table, "killswitch"];
                argv.extend(body.iter().map(String::as_str));
                nft_ns(h, &argv);
            }
        };
        // Generation table in the daemon's order: `ensure_failclosed_table`
        // adds the overlay WireGuard allows (the daemon's
        // `wg_listen_port_allow_tokens(.., overlay, ..)` shape) and the
        // transit rules BEFORE `apply_firewall_killswitch` adds the
        // established/related trio.
        base_chain(&generation);
        for port_match in ["dport", "sport"] {
            nft_ns(
                h,
                &[
                    "add",
                    "rule",
                    "inet",
                    &generation,
                    "killswitch",
                    "oifname",
                    "rustynet-vx0",
                    "meta",
                    "nfproto",
                    "ipv4",
                    "udp",
                    port_match,
                    WG_PORT,
                    "accept",
                ],
            );
        }
        if shape.gen_transit {
            for peer in transit.peers() {
                let body = substrate_transit_allow_tokens(UNDERLAY, *peer);
                let mut argv = vec!["add", "rule", "inet", generation.as_str(), "killswitch"];
                argv.extend(body.iter().map(String::as_str));
                nft_ns(h, &argv);
            }
        }
        established(&generation);
        // Boot table in the boot installer's order: interface-agnostic
        // WireGuard allows (finding 13), then the installer's transit argv
        // bodies appended last, table renamed.
        base_chain(&boot);
        established(&boot);
        for port_match in ["dport", "sport"] {
            nft_ns(
                h,
                &[
                    "add",
                    "rule",
                    "inet",
                    &boot,
                    "killswitch",
                    "udp",
                    port_match,
                    WG_PORT,
                    "accept",
                ],
            );
        }
        if shape.boot_transit {
            for argv in crate::linux_killswitch_boot::boot_substrate_transit_rule_argvs(&transit) {
                let mut renamed: Vec<&str> =
                    vec!["add", "rule", "inet", boot.as_str(), "killswitch"];
                renamed.extend(argv.iter().skip(5).map(String::as_str));
                nft_ns(h, &renamed);
            }
        }
    }

    /// Send the "WireGuard" datagram (UDP 51820 -> peer overlay :51820) from
    /// H; returns (received by P, H-side send errors).
    fn probe(netns: &Netns, sport: u16, dport: u16) -> (bool, String) {
        let receiver_code = format!(
            "import socket\ns=socket.socket(2,2)\ns.bind(('0.0.0.0',{dport}))\ns.settimeout(4)\n\
             try:\n    print(s.recvfrom(64)[0].decode())\nexcept Exception as e:\n    print('timeout')\n"
        );
        let receiver_argv = in_ns(&netns.p, &["python3", "-c", &receiver_code]);
        let receiver = std::process::Command::new(&receiver_argv[0])
            .args(&receiver_argv[1..])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn receiver");
        std::thread::sleep(std::time::Duration::from_millis(400));
        let sender_code = format!(
            "import socket,time\ns=socket.socket(2,2)\ns.bind(('0.0.0.0',{sport}))\nerrs=[]\n\
             for i in range(6):\n    try:\n        s.sendto(b'rn-probe',('172.31.0.2',{dport}))\n\
             \x20   except OSError as e:\n        errs.append(e.errno)\n    time.sleep(0.3)\n\
             print(','.join(str(e) for e in errs))\n"
        );
        let sender = must_ns(&netns.h, &["python3", "-c", &sender_code]);
        let output = receiver.wait_with_output().expect("receiver output");
        let received = String::from_utf8_lossy(&output.stdout).trim() == "rn-probe";
        (received, sender.trim().to_owned())
    }

    fn transit_counter(netns: &Netns, table: &str) -> u64 {
        let listing = must_ns(
            &netns.h,
            &["nft", "list", "chain", "inet", table, "killswitch"],
        );
        listing
            .lines()
            .find(|line| line.contains("rustynet_substrate_transit"))
            .and_then(|line| {
                let tokens: Vec<&str> = line.split_whitespace().collect();
                let at = tokens.iter().position(|token| *token == "packets")?;
                tokens.get(at + 1)?.parse().ok()
            })
            .unwrap_or(0)
    }

    #[test]
    #[ignore = "needs root, ip, nft and python3; runs only inside throwaway netns"]
    fn netns_witness_design_d() {
        assert!(
            nix::unistd::geteuid().is_root(),
            "run as root (sudo -n) on a Linux lab box"
        );
        let base = format!("rn_impl_{}", std::process::id());
        let mut report = Vec::new();

        // Control: no killswitch at all.
        let netns = build(
            &format!("{base}c"),
            Shape {
                killswitch: false,
                ..DESIGN_D
            },
        );
        let (received, errs) = probe(&netns, 51820, 51820);
        report.push(format!(
            "control no killswitch: received={received} errs=[{errs}]"
        ));
        assert!(received, "control must deliver");
        drop(netns);

        // A3 + D2 + R: the whole design D delivers, both transit counters move.
        let tag = format!("{base}d");
        let netns = build(&tag, DESIGN_D);
        let route = must_ns(&netns.h, &["ip", "route", "get", PEER_UNDERLAY_IP]);
        let (received, errs) = probe(&netns, 51820, 51820);
        let gen_count = transit_counter(&netns, &format!("{tag}_gen"));
        let boot_count = transit_counter(&netns, &format!("{tag}_boot"));
        report.push(format!(
            "design D (gen+boot transit, srcport pinned, /32 pin): received={received} \
             errs=[{errs}] gen_counter={gen_count} boot_counter={boot_count} route={}",
            route.trim()
        ));
        assert!(received, "design D must deliver");
        assert!(
            gen_count > 0 && boot_count > 0,
            "both transit rules must count"
        );
        assert!(route.contains("via 10.99.0.254 dev ua") && route.contains("table 51820"));

        // A4: non-WireGuard inner traffic over the overlay is still dropped.
        let (received, errs) = probe(&netns, 40000, 9999);
        report.push(format!(
            "A4 inner udp 40000->9999: received={received} errs=[{errs}]"
        ));
        assert!(!received, "non-WireGuard inner traffic must be dropped");
        let ping = cmd(
            &in_ns(&netns.h, &["ping", "-c", "2", "-W", "1", "172.31.0.2"])
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        );
        report.push(format!(
            "A4 ping overlay: success={}",
            ping.status.success()
        ));
        assert!(
            !ping.status.success(),
            "ping over the overlay must be dropped"
        );

        // A5: nothing but the kernel vxlan socket can hold or forge 4789.
        let bind_code = "import socket\ns=socket.socket(2,2)\ntry:\n    s.bind(('0.0.0.0',4789))\n    print('bound')\nexcept OSError as e:\n    print(e.errno)\n";
        let root_bind = must_ns(&netns.h, &["python3", "-c", bind_code]);
        let nobody_bind = must_ns(
            &netns.h,
            &[
                "setpriv",
                "--reuid=65534",
                "--regid=65534",
                "--clear-groups",
                "python3",
                "-c",
                bind_code,
            ],
        );
        let forge_code = "import socket\ns=socket.socket(2,2)\ntry:\n    s.sendto(b'x',('10.98.0.2',4789))\n    print('sent')\nexcept OSError as e:\n    print(e.errno)\n";
        let forged = must_ns(&netns.h, &["python3", "-c", forge_code]);
        report.push(format!(
            "A5 bind 4789 root={} nobody={} random-sport datagram to peer:4789={}",
            root_bind.trim(),
            nobody_bind.trim(),
            forged.trim()
        ));
        assert_eq!(root_bind.trim(), "98", "EADDRINUSE for root");
        assert_eq!(nobody_bind.trim(), "98", "EADDRINUSE for nobody");
        assert_eq!(forged.trim(), "1", "EPERM for a random source port");

        // Render: the real nft rendering of the builder rule is the golden line.
        let render_table = format!("{tag}_render");
        nft_ns(&netns.h, &["add", "table", "inet", &render_table]);
        nft_ns(
            &netns.h,
            &[
                "add",
                "chain",
                "inet",
                &render_table,
                "killswitch",
                "{",
                "type",
                "filter",
                "hook",
                "output",
                "priority",
                "0",
                ";",
                "policy",
                "accept",
                ";",
                "}",
            ],
        );
        let body = substrate_transit_allow_tokens("eth0", "192.168.122.31".parse().expect("ip"));
        let mut argv = vec!["add", "rule", "inet", render_table.as_str(), "killswitch"];
        argv.extend(body.iter().map(String::as_str));
        nft_ns(&netns.h, &argv);
        let listing = must_ns(
            &netns.h,
            &["nft", "list", "chain", "inet", &render_table, "killswitch"],
        );
        let rendered = listing
            .lines()
            .map(str::trim)
            .find(|line| line.contains("rustynet_substrate_transit"))
            .unwrap_or_default()
            .to_owned();
        report.push(format!("render: {rendered}"));
        assert_eq!(
            rendered,
            "oifname \"eth0\" ip daddr 192.168.122.31 udp sport 4789 udp dport 4789 counter \
             packets 0 bytes 0 accept comment \"rustynet_substrate_transit\""
        );
        drop(netns);

        // Negative shapes: each missing piece of design D stops delivery.
        for (shape_index, label) in [
            (
                "A1 no transit rule in either table",
                Shape {
                    gen_transit: false,
                    boot_transit: false,
                    ..DESIGN_D
                },
            ),
            (
                "D1 generation transit only (boot table drops)",
                Shape {
                    boot_transit: false,
                    ..DESIGN_D
                },
            ),
            (
                "D1b boot transit only (generation table drops)",
                Shape {
                    gen_transit: false,
                    ..DESIGN_D
                },
            ),
            (
                "A2 vxlan source port not pinned",
                Shape {
                    srcport_pinned: false,
                    ..DESIGN_D
                },
            ),
            (
                "R no /32 pin under full tunnel",
                Shape {
                    pin: false,
                    ..DESIGN_D
                },
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let (label, shape) = label;
            let netns = build(&format!("{base}n{shape_index}"), shape);
            let route = must_ns(&netns.h, &["ip", "route", "get", PEER_UNDERLAY_IP]);
            let (received, errs) = probe(&netns, 51820, 51820);
            report.push(format!(
                "{label}: received={received} errs=[{errs}] route={}",
                route.trim()
            ));
            assert!(!received, "{label} must NOT deliver");
            drop(netns);
        }
        // D3: why the live proof reads the transit COUNTERS. With no transit
        // rule at all, a frame the PEER sends first makes H's encapsulation
        // the reply direction of one 4789<->4789 conntrack tuple, and the
        // established accept carries it.
        let netns = build(
            &format!("{base}m"),
            Shape {
                gen_transit: false,
                boot_transit: false,
                ..DESIGN_D
            },
        );
        must_ns(
            &netns.p,
            &[
                "python3",
                "-c",
                "import socket\ns=socket.socket(2,2)\ns.bind(('0.0.0.0',51820))\n\
                 s.sendto(b'peer-first',('172.31.0.1',51820))\n",
            ],
        );
        std::thread::sleep(std::time::Duration::from_millis(800));
        let (received, errs) = probe(&netns, 51820, 51820);
        report.push(format!(
            "D3 no transit rule, PEER sends first (conntrack carries it): received={received} \
             errs=[{errs}]"
        ));
        assert!(received, "D3: conntrack masks a missing transit rule");
        drop(netns);
        println!("NETNS WITNESS (design D):\n{}", report.join("\n"));
    }
}
