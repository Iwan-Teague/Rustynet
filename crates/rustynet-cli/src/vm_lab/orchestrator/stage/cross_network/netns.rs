//! CN-2 of `CrossNetworkSubstrateIntegrationSpec_2026-06-21.md` §0.4: the
//! Tier-A netns substrate, ported from `scripts/vm_lab/netns_internet_sim.sh`
//! (topology), `netns_nat_classify.sh` (mapping gate) and
//! `netns_nat_filter.sh` (filtering gate) onto [`NetLeafRunner`].
//!
//! WHAT THIS IS. A deterministic "internet in a box" built from Linux network
//! namespaces inside ONE lab guest: a `rnsim-wan` bridge is the simulated
//! transit, `rnsim-svc` hosts the STUN responders, and each site is a
//! `rnsim-rtr-<name>` router NAT'ing a `rnsim-ep-<name>` endpoint on its own
//! private /24. It needs no second network, so it is the only cross-network
//! path provable on one host today.
//!
//! WHAT THIS IS NOT. It is not a topology-level overlay. Its endpoints are
//! namespaces inside one guest, not lab node aliases, so it provisions NO
//! overlay address for any alias and therefore never rewrites `ctx.endpoints`
//! (spec §3: "Tier A = the deterministic NAT-matrix gate", it does not run the
//! SSH e2e validators). The topology-level seam stays vxlan-only; see
//! `substrate::topology_level_provider`.
//!
//! WHY IT IS NOT SHELL ANY MORE. AGENTS.md §4 requires superseded shell
//! implementations to leave active paths during the shell-to-Rust migration.
//! The orchestrator used to `scp` three bash scripts to the exit guest and
//! `sudo -n bash` them; a non-zero exit was all the evidence it produced. The
//! port keeps the exact same kernel leaf ops (`ip`/`nft`/`tc`, argv-only —
//! `unsafe` netlink is forbidden workspace-wide) but owns the sequence, the
//! errors, the per-check evidence rows and the teardown in typed Rust.
//!
//! COST NOTE. Every leaf op is one SSH round trip, where the shell ran the
//! whole sequence in a single remote session. The gates below rebuild the
//! topology per profile/scenario exactly as the shell did (a fresh conntrack
//! state is the point), so this trades wall clock for typed evidence and
//! deterministic teardown. SSH `ControlMaster` multiplexing on
//! `build_ssh_command` is the obvious future optimisation; it is deliberately
//! NOT taken here because a persistent control socket is itself residue.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

use super::substrate::{
    CreatedResource, CrossNetworkSubstrateProvider, LeafOutput, NatApplyError, NatModifiers,
    NatProfileId, NetLeafRunner, SiteRef, SubstrateHandle, SubstrateRecord, SubstrateSetupFailure,
    SubstrateTopology, Support, topology_digest, validate_argv, validate_netns_name,
};

/// Every namespace, bridge and veth this substrate creates carries this
/// prefix. Teardown sweeps exactly it, and the final-cleanup residue assert
/// can key on it.
pub const NS_PREFIX: &str = "rnsim-";
/// The simulated-transit bridge ("the internet").
pub const WAN_BRIDGE: &str = "rnsim-wan";
/// Services namespace: STUN responders live here.
pub const SVC_NS: &str = "rnsim-svc";
/// The services namespace's interface.
pub const SVC_IF: &str = "rnsim-svc-w";
/// Its bridge-side peer.
pub const SVC_BRIDGE_IF: &str = "rnsim-svc-br";
/// Simulated transit lives in the IANA benchmarking range 198.18.0.0/15
/// (`LiveLabVmConnectivityRulebook` §15.3). The legacy 100.64.0.0/24 default
/// overlapped the Rustynet mesh 100.64.0.0/10 — a collision
/// `vm-lab-network-audit` still flags as an error, and which
/// [`wan_cidr_does_not_collide_with_the_mesh`] pins at compile-and-test time
/// now that the value is a Rust constant rather than a shell variable.
pub const WAN_BASE: &str = "198.18.0";
/// Primary STUN service host octet.
pub const SVC_PRIMARY_OCTET: u8 = 254;
/// Secondary STUN service host octet — the second, DISTINCT destination the
/// mapping gate needs to tell endpoint-independent from endpoint-dependent.
pub const SVC_SECONDARY_OCTET: u8 = 253;
/// Low/high of the UDP range `full_cone` DNATs inbound to the endpoint.
pub const UDP_PORT_LO: u16 = 51820;
pub const UDP_PORT_HI: u16 = 51900;
/// STUN port the responders bind.
pub const STUN_PORT: u16 = 3478;
/// The endpoint's WireGuard-shaped bind port in the filtering gate.
pub const EP_WG_PORT: u16 = 51820;
/// Where `run_nat_classification` stages the Rust probe on the guest.
pub const PROBE_BIN: &str = "/tmp/rustynet-netns-probe";

/// The mesh overlay the simulated transit must never collide with.
const MESH_OVERLAY_FIRST_OCTET: u8 = 100;

/// Second octet of the carrier segment (see [`CGN_SECOND_OCTET`]).
const CGN_FIRST_OCTET: u8 = 100;
/// Third-octet base for the `double_nat_cgnat` carrier segment: site `i` links
/// its home router to its carrier router over `100.64.<200+i>.0/24`.
///
/// This is RFC 6598 shared address space **on purpose**, and it is the one
/// place in this module that deliberately overlaps the Rustynet mesh's
/// 100.64.0.0/10. The whole point of `double_nat_cgnat` is that the address
/// between the two NAT hops is carrier-grade space: the daemon's CGNAT
/// detection (dataplane plan §4.1.3 — "uPnP-WAN vs STUN mismatch, or
/// 100.64.0.0/10 WAN") reads exactly that, so numbering it out of the
/// benchmarking range the rest of the simulator uses would make the stage
/// prove nothing. `scripts/vm_lab/apply_nat_profile.sh` makes the same choice
/// (`CGN_HOME_ADDR=100.64.10.2/24`).
///
/// The overlap is safe because the segment exists ONLY on the veth between a
/// site's `rnsim-rtr-*` and `rnsim-cgn-*` namespaces — it is never on the
/// simulated transit, never on an endpoint namespace, and never in the guest's
/// root namespace where a real mesh interface could live. The /24 is taken
/// from the top of the third octet to stay clear of the low addresses a lab
/// mesh actually allocates.
const CGN_SECOND_OCTET: u8 = 64;
const CGN_THIRD_OCTET_BASE: u8 = 200;

/// The carrier segment for site `idx`: `100.64.<200+idx>.0/24`.
fn cgn_base(idx: usize) -> String {
    format!(
        "{CGN_FIRST_OCTET}.{CGN_SECOND_OCTET}.{}",
        CGN_THIRD_OCTET_BASE.saturating_add(idx as u8)
    )
}

/// Maximum sites: site `i` takes `10.<10*i>.0.0/24` and WAN host `10 + i`, so
/// the WAN /24 runs out well before the LAN space does.
const MAX_SITES: usize = 20;

fn svc_primary() -> String {
    format!("{WAN_BASE}.{SVC_PRIMARY_OCTET}")
}

fn svc_secondary() -> String {
    format!("{WAN_BASE}.{SVC_SECONDARY_OCTET}")
}

/// Site `idx`'s router WAN address — the address an unsolicited inbound probe
/// targets in the `COLD_INBOUND` filtering scenario.
fn site_wan_ip(idx: usize) -> String {
    format!("{WAN_BASE}.{}", 10 + idx)
}

// ───────────────────────────── sudo wrapper ─────────────────────────────

/// Wraps a runner so every leaf op executes as `sudo -n <argv…>`.
///
/// It exists so namespace execution keeps going through
/// [`NetLeafRunner::in_netns`] — the provided method that allowlist-validates
/// the namespace name before it enters argv. Prefixing by hand
/// (`["sudo","-n","ip","netns","exec", ns, …]`) would bypass that validation,
/// which is exactly the shell-construction hole the trait was shaped to close.
/// Composing the sudo prefix UNDER `in_netns` yields
/// `sudo -n ip netns exec <validated-ns> …` with the check intact.
pub struct SudoRunner<'a> {
    inner: &'a dyn NetLeafRunner,
}

impl<'a> SudoRunner<'a> {
    pub fn new(inner: &'a dyn NetLeafRunner) -> Self {
        Self { inner }
    }
}

impl NetLeafRunner for SudoRunner<'_> {
    fn run(&self, argv: &[&str]) -> Result<LeafOutput, String> {
        validate_argv(argv)?;
        let mut full: Vec<&str> = vec!["sudo", "-n"];
        full.extend_from_slice(argv);
        self.inner.run(&full)
    }
}

/// Run a command that must succeed: a transport failure and a non-zero exit
/// both fail closed, with the guest's own stderr in the message.
fn required(runner: &dyn NetLeafRunner, argv: &[&str]) -> Result<LeafOutput, String> {
    let output = runner.run(argv).map_err(|err| format!("{argv:?}: {err}"))?;
    if output.success {
        Ok(output)
    } else {
        Err(format!("{argv:?} failed: {}", output.stderr.trim()))
    }
}

/// As [`required`], but inside a network namespace.
fn required_in_ns(
    runner: &dyn NetLeafRunner,
    ns: &str,
    argv: &[&str],
) -> Result<LeafOutput, String> {
    let output = runner
        .in_netns(ns, argv)
        .map_err(|err| format!("{ns}: {argv:?}: {err}"))?;
    if output.success {
        Ok(output)
    } else {
        Err(format!("{ns}: {argv:?} failed: {}", output.stderr.trim()))
    }
}

// ───────────────────────────── site model ─────────────────────────────

/// Optional netem impairment applied to the endpoint's uplink. A closed set:
/// the shell's free-form string could reach `tc` unvalidated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetnsImpairment {
    None,
    Latency50msLoss1pct,
    Latency120msLoss3pct,
    Loss5pct,
}

impl NetnsImpairment {
    /// Parse an impairment name, fail-closed on anything unknown.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim() {
            "none" | "" => Ok(Self::None),
            "latency_50ms_loss_1pct" => Ok(Self::Latency50msLoss1pct),
            "latency_120ms_loss_3pct" => Ok(Self::Latency120msLoss3pct),
            "loss_5pct" => Ok(Self::Loss5pct),
            other => Err(format!(
                "unknown netns impairment {other:?}; expected \
                 none|latency_50ms_loss_1pct|latency_120ms_loss_3pct|loss_5pct"
            )),
        }
    }

    /// The `tc qdisc … netem` tail, or empty when there is nothing to apply.
    fn netem_argv(self) -> &'static [&'static str] {
        match self {
            Self::None => &[],
            Self::Latency50msLoss1pct => &["delay", "50ms", "loss", "1%"],
            Self::Latency120msLoss3pct => &[
                "delay",
                "120ms",
                "20ms",
                "distribution",
                "normal",
                "loss",
                "3%",
            ],
            Self::Loss5pct => &["loss", "5%"],
        }
    }
}

/// One simulated home network: an endpoint behind a router applying `profile`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetnsSite {
    name: String,
    profile: NatProfileId,
    impairment: NetnsImpairment,
}

impl NetnsSite {
    /// Build a site. The name becomes part of two namespace names, so it is
    /// validated here — before it can reach argv — against the same allowlist
    /// `in_netns` applies, plus a length bound that keeps the derived
    /// `rnsim-rtr-<name>` inside the `/var/run/netns` filename limit.
    pub fn new(
        name: &str,
        profile: NatProfileId,
        impairment: NetnsImpairment,
    ) -> Result<Self, String> {
        if name.is_empty() {
            return Err("netns site name must not be empty".to_owned());
        }
        if name.len() > 32 {
            return Err(format!("netns site name exceeds 32 bytes: {name:?}"));
        }
        // Defence in depth: the name only ever reaches argv embedded in
        // `rnsim-rtr-<name>`, which cannot look like an option — but an
        // option-shaped site name is confusing enough in evidence that it is
        // refused outright rather than relying on that embedding to hold.
        if name.starts_with('-') {
            return Err(format!(
                "netns site name must not look like an option: {name:?}"
            ));
        }
        if !name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
        {
            return Err(format!(
                "netns site name must contain only ASCII letters, digits, '_' or '-': {name:?}"
            ));
        }
        // Belt and braces: the derived namespace names must themselves pass
        // the runner's validator, so a name that is fine alone but produces a
        // bad namespace never reaches the guest.
        validate_netns_name(&format!("{NS_PREFIX}rtr-{name}"))?;
        validate_netns_name(&format!("{NS_PREFIX}ep-{name}"))?;
        validate_netns_name(&format!("{NS_PREFIX}cgn-{name}"))?;
        Ok(Self {
            name: name.to_owned(),
            profile,
            impairment,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn profile(&self) -> &NatProfileId {
        &self.profile
    }

    fn router_ns(&self) -> String {
        format!("{NS_PREFIX}rtr-{}", self.name)
    }

    fn endpoint_ns(&self) -> String {
        format!("{NS_PREFIX}ep-{}", self.name)
    }

    /// The carrier ("ISP") namespace chained behind the home router. Only
    /// built for `double_nat_cgnat`.
    fn carrier_ns(&self) -> String {
        format!("{NS_PREFIX}cgn-{}", self.name)
    }

    /// True when this site needs the second, carrier NAT hop.
    fn is_double_nat(&self) -> bool {
        self.profile.as_str() == "double_nat_cgnat"
    }
}

// ───────────────────────────── the provider ─────────────────────────────

/// The Tier-A netns provider (spec §0.4 CN-2).
pub struct NetnsSubstrateProvider {
    host_alias: String,
    sites: Vec<NetnsSite>,
}

impl NetnsSubstrateProvider {
    /// Build a provider bound to the guest that will host the simulator.
    /// Fails closed on an empty site list, on more sites than the WAN /24
    /// addressing plan holds, and on duplicate site names (two sites sharing a
    /// name would collide on namespace names and silently overwrite).
    pub fn new(host_alias: &str, sites: Vec<NetnsSite>) -> Result<Self, String> {
        if host_alias.is_empty() {
            return Err("netns substrate needs a host alias".to_owned());
        }
        if sites.is_empty() {
            return Err("netns substrate needs at least one site".to_owned());
        }
        if sites.len() > MAX_SITES {
            return Err(format!(
                "netns substrate supports at most {MAX_SITES} sites; {} requested",
                sites.len()
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        for site in &sites {
            if !seen.insert(site.name.clone()) {
                return Err(format!("duplicate netns site name {:?}", site.name));
            }
        }
        Ok(Self {
            host_alias: host_alias.to_owned(),
            sites,
        })
    }

    /// A single-site provider — what both NAT gates below drive.
    pub fn single_site(
        host_alias: &str,
        site_name: &str,
        profile: NatProfileId,
    ) -> Result<Self, String> {
        Self::new(
            host_alias,
            vec![NetnsSite::new(site_name, profile, NetnsImpairment::None)?],
        )
    }

    pub fn sites(&self) -> &[NetnsSite] {
        &self.sites
    }

    fn runner_for<'a>(
        &self,
        runners: &'a BTreeMap<String, &'a dyn NetLeafRunner>,
    ) -> Result<&'a dyn NetLeafRunner, String> {
        runners
            .get(&self.host_alias)
            .copied()
            .ok_or_else(|| format!("no leaf runner for netns host '{}'", self.host_alias))
    }

    fn empty_handle(&self, topology: &SubstrateTopology, provisioned: bool) -> SubstrateHandle {
        SubstrateHandle {
            record: SubstrateRecord {
                substrate_id: self.id().to_owned(),
                topology_digest: topology_digest(self.id(), topology, None),
                provisioned,
                participants: vec![self.host_alias.clone()],
            },
            // Deliberately EMPTY: the netns substrate provisions no overlay
            // address for any lab alias, so `SubstrateHandle::endpoint()`
            // answers on the underlay plane and `collect_pubkeys` leaves every
            // discovered endpoint alone.
            overlay_ips: BTreeMap::new(),
            underlay_ips: topology
                .nodes
                .iter()
                .map(|(alias, ip)| (alias.clone(), ip.to_string()))
                .collect(),
            created_resources: Vec::new(),
        }
    }

    /// The wan bridge + services namespace.
    fn build_wan_core(
        &self,
        runner: &dyn NetLeafRunner,
        handle: &mut SubstrateHandle,
    ) -> Result<(), String> {
        let alias = self.host_alias.clone();
        required(runner, &["ip", "link", "add", WAN_BRIDGE, "type", "bridge"])?;
        handle
            .created_resources
            .push(CreatedResource::link(&alias, WAN_BRIDGE));
        required(runner, &["ip", "link", "set", WAN_BRIDGE, "up"])?;

        required(runner, &["ip", "netns", "add", SVC_NS])?;
        handle
            .created_resources
            .push(CreatedResource::netns(&alias, SVC_NS));
        required(
            runner,
            &[
                "ip",
                "link",
                "add",
                SVC_IF,
                "type",
                "veth",
                "peer",
                "name",
                SVC_BRIDGE_IF,
            ],
        )?;
        handle
            .created_resources
            .push(CreatedResource::link(&alias, SVC_BRIDGE_IF));
        required(runner, &["ip", "link", "set", SVC_IF, "netns", SVC_NS])?;
        required(
            runner,
            &["ip", "link", "set", SVC_BRIDGE_IF, "master", WAN_BRIDGE],
        )?;
        required(runner, &["ip", "link", "set", SVC_BRIDGE_IF, "up"])?;

        // Both service addresses are provisioned here. The shell added the
        // secondary ad hoc inside each gate script with `|| true`, so a
        // failure to add it produced a confusing "endpoint-dependent" verdict
        // instead of an error; here it is part of the topology and fails
        // closed.
        for octet in [SVC_PRIMARY_OCTET, SVC_SECONDARY_OCTET] {
            let cidr = format!("{WAN_BASE}.{octet}/24");
            required_in_ns(runner, SVC_NS, &["ip", "addr", "add", &cidr, "dev", SVC_IF])?;
        }
        required_in_ns(runner, SVC_NS, &["ip", "link", "set", SVC_IF, "up"])?;
        required_in_ns(runner, SVC_NS, &["ip", "link", "set", "lo", "up"])?;
        Ok(())
    }

    /// One site: router + endpoint namespaces, their veths, addressing,
    /// optional impairment, forwarding, and the NAT profile.
    fn build_site(
        &self,
        runner: &dyn NetLeafRunner,
        handle: &mut SubstrateHandle,
        idx: usize,
        site: &NetnsSite,
    ) -> Result<(), String> {
        let alias = self.host_alias.clone();
        let router_ns = site.router_ns();
        let endpoint_ns = site.endpoint_ns();
        let lan_net = format!("10.{}.0", idx * 10);
        let ep_ip = format!("{lan_net}.2");
        let gw_ip = format!("{lan_net}.1");
        let wan_ip = site_wan_ip(idx);
        let router_wan_if = format!("{NS_PREFIX}r{idx}w");
        let router_wan_br = format!("{NS_PREFIX}r{idx}br");
        let ep_lan_if = format!("{NS_PREFIX}e{idx}l");
        let router_lan_if = format!("{NS_PREFIX}r{idx}l");

        let carrier_ns = site.carrier_ns();
        let mut namespaces: Vec<&String> = vec![&router_ns, &endpoint_ns];
        if site.is_double_nat() {
            namespaces.push(&carrier_ns);
        }
        for ns in namespaces {
            required(runner, &["ip", "netns", "add", ns])?;
            handle
                .created_resources
                .push(CreatedResource::netns(&alias, ns));
            required_in_ns(runner, ns, &["ip", "link", "set", "lo", "up"])?;
        }

        // The namespace that faces the simulated transit and carries the site's
        // WAN address. For a single-hop profile that is the site router itself;
        // for `double_nat_cgnat` it is the carrier, and the home router reaches
        // it over the RFC 6598 segment built below — two translations between
        // the endpoint and the transit, which is the whole point of the profile.
        let wan_facing_ns = if site.is_double_nat() {
            carrier_ns.clone()
        } else {
            router_ns.clone()
        };

        // wan-facing namespace ↔ wan bridge
        required(
            runner,
            &[
                "ip",
                "link",
                "add",
                &router_wan_if,
                "type",
                "veth",
                "peer",
                "name",
                &router_wan_br,
            ],
        )?;
        handle
            .created_resources
            .push(CreatedResource::link(&alias, &router_wan_br));
        required(
            runner,
            &["ip", "link", "set", &router_wan_if, "netns", &wan_facing_ns],
        )?;
        required(
            runner,
            &["ip", "link", "set", &router_wan_br, "master", WAN_BRIDGE],
        )?;
        required(runner, &["ip", "link", "set", &router_wan_br, "up"])?;
        let wan_cidr = format!("{wan_ip}/24");
        required_in_ns(
            runner,
            &wan_facing_ns,
            &["ip", "addr", "add", &wan_cidr, "dev", &router_wan_if],
        )?;
        required_in_ns(
            runner,
            &wan_facing_ns,
            &["ip", "link", "set", &router_wan_if, "up"],
        )?;

        // The carrier segment: home router ──100.64.<200+idx>.0/24── carrier.
        let cgn_home_if = format!("{NS_PREFIX}h{idx}c");
        let cgn_carrier_if = format!("{NS_PREFIX}c{idx}h");
        if site.is_double_nat() {
            let cgn = cgn_base(idx);
            let home_ip = format!("{cgn}.2");
            let carrier_ip = format!("{cgn}.1");
            required(
                runner,
                &[
                    "ip",
                    "link",
                    "add",
                    &cgn_home_if,
                    "type",
                    "veth",
                    "peer",
                    "name",
                    &cgn_carrier_if,
                ],
            )?;
            handle
                .created_resources
                .push(CreatedResource::link(&alias, &cgn_home_if));
            required(
                runner,
                &["ip", "link", "set", &cgn_home_if, "netns", &router_ns],
            )?;
            required(
                runner,
                &["ip", "link", "set", &cgn_carrier_if, "netns", &carrier_ns],
            )?;
            let home_cidr = format!("{home_ip}/24");
            let carrier_cidr = format!("{carrier_ip}/24");
            required_in_ns(
                runner,
                &router_ns,
                &["ip", "addr", "add", &home_cidr, "dev", &cgn_home_if],
            )?;
            required_in_ns(
                runner,
                &router_ns,
                &["ip", "link", "set", &cgn_home_if, "up"],
            )?;
            required_in_ns(
                runner,
                &carrier_ns,
                &["ip", "addr", "add", &carrier_cidr, "dev", &cgn_carrier_if],
            )?;
            required_in_ns(
                runner,
                &carrier_ns,
                &["ip", "link", "set", &cgn_carrier_if, "up"],
            )?;
            // The home router's only way out is the carrier.
            required_in_ns(
                runner,
                &router_ns,
                &["ip", "route", "add", "default", "via", &carrier_ip],
            )?;
            required_in_ns(
                runner,
                &carrier_ns,
                &["sysctl", "-qw", "net.ipv4.ip_forward=1"],
            )?;
            // Outer hop: the carrier masquerades the whole RFC 6598 segment
            // onto the transit, with randomised source ports — carrier NATs are
            // typically endpoint-dependent, and NO uPnP is offered here, which
            // is what makes the CGNAT case unmappable from inside.
            required_in_ns(
                runner,
                &carrier_ns,
                &["nft", "add", "table", "ip", "rnsim_nat"],
            )?;
            required_in_ns(
                runner,
                &carrier_ns,
                &[
                    "nft",
                    "add",
                    "chain",
                    "ip",
                    "rnsim_nat",
                    "post",
                    "{ type nat hook postrouting priority srcnat; policy accept; }",
                ],
            )?;
            required_in_ns(
                runner,
                &carrier_ns,
                &[
                    "nft",
                    "add",
                    "rule",
                    "ip",
                    "rnsim_nat",
                    "post",
                    "oifname",
                    &router_wan_if,
                    "masquerade",
                    "random",
                ],
            )?;
        }

        // endpoint ↔ router (the simulated home LAN)
        required(
            runner,
            &[
                "ip",
                "link",
                "add",
                &ep_lan_if,
                "type",
                "veth",
                "peer",
                "name",
                &router_lan_if,
            ],
        )?;
        handle
            .created_resources
            .push(CreatedResource::link(&alias, &ep_lan_if));
        required(
            runner,
            &["ip", "link", "set", &ep_lan_if, "netns", &endpoint_ns],
        )?;
        required(
            runner,
            &["ip", "link", "set", &router_lan_if, "netns", &router_ns],
        )?;
        let gw_cidr = format!("{gw_ip}/24");
        required_in_ns(
            runner,
            &router_ns,
            &["ip", "addr", "add", &gw_cidr, "dev", &router_lan_if],
        )?;
        required_in_ns(
            runner,
            &router_ns,
            &["ip", "link", "set", &router_lan_if, "up"],
        )?;
        let ep_cidr = format!("{ep_ip}/24");
        required_in_ns(
            runner,
            &endpoint_ns,
            &["ip", "addr", "add", &ep_cidr, "dev", &ep_lan_if],
        )?;
        required_in_ns(
            runner,
            &endpoint_ns,
            &["ip", "link", "set", &ep_lan_if, "up"],
        )?;
        required_in_ns(
            runner,
            &endpoint_ns,
            &["ip", "route", "add", "default", "via", &gw_ip],
        )?;

        let netem = site.impairment.netem_argv();
        if !netem.is_empty() {
            let mut argv: Vec<&str> =
                vec!["tc", "qdisc", "add", "dev", &ep_lan_if, "root", "netem"];
            argv.extend_from_slice(netem);
            required_in_ns(runner, &endpoint_ns, &argv)?;
        }

        required_in_ns(
            runner,
            &router_ns,
            &["sysctl", "-qw", "net.ipv4.ip_forward=1"],
        )?;
        // The site router's UPLINK interface: the transit-facing veth normally,
        // the carrier-facing veth when a carrier hop sits behind it.
        let router_uplink_if = if site.is_double_nat() {
            cgn_home_if.as_str()
        } else {
            router_wan_if.as_str()
        };
        self.apply_site_nat(runner, site, router_uplink_if, &ep_ip)
    }

    /// The NAT profile, as nftables rules inside the router namespace. Same
    /// semantics as `netns_internet_sim.sh:apply_site_nat`.
    fn apply_site_nat(
        &self,
        runner: &dyn NetLeafRunner,
        site: &NetnsSite,
        wan_if: &str,
        ep_ip: &str,
    ) -> Result<(), String> {
        let ns = site.router_ns();
        required_in_ns(runner, &ns, &["nft", "add", "table", "ip", "rnsim_nat"])?;
        required_in_ns(
            runner,
            &ns,
            &[
                "nft",
                "add",
                "chain",
                "ip",
                "rnsim_nat",
                "post",
                "{ type nat hook postrouting priority srcnat; policy accept; }",
            ],
        )?;
        match site.profile.as_str() {
            // Inner ("home router") hop of the carrier chain: a plain
            // masquerade onto the RFC 6598 segment. The outer, port-randomising
            // carrier hop is built in `build_site` inside `rnsim-cgn-*`, so the
            // finished site has TWO translations between the endpoint and the
            // transit.
            "double_nat_cgnat" | "port_restricted_cone" => {
                required_in_ns(
                    runner,
                    &ns,
                    &[
                        "nft",
                        "add",
                        "rule",
                        "ip",
                        "rnsim_nat",
                        "post",
                        "oifname",
                        wan_if,
                        "masquerade",
                    ],
                )?;
            }
            "symmetric" => {
                required_in_ns(
                    runner,
                    &ns,
                    &[
                        "nft",
                        "add",
                        "rule",
                        "ip",
                        "rnsim_nat",
                        "post",
                        "oifname",
                        wan_if,
                        "masquerade",
                        "random",
                    ],
                )?;
            }
            "full_cone" => {
                required_in_ns(
                    runner,
                    &ns,
                    &[
                        "nft",
                        "add",
                        "rule",
                        "ip",
                        "rnsim_nat",
                        "post",
                        "oifname",
                        wan_if,
                        "masquerade",
                    ],
                )?;
                required_in_ns(
                    runner,
                    &ns,
                    &[
                        "nft",
                        "add",
                        "chain",
                        "ip",
                        "rnsim_nat",
                        "pre",
                        "{ type nat hook prerouting priority dstnat; policy accept; }",
                    ],
                )?;
                let dport = format!("{UDP_PORT_LO}-{UDP_PORT_HI}");
                required_in_ns(
                    runner,
                    &ns,
                    &[
                        "nft",
                        "add",
                        "rule",
                        "ip",
                        "rnsim_nat",
                        "pre",
                        "iifname",
                        wan_if,
                        "udp",
                        "dport",
                        &dport,
                        "dnat",
                        "to",
                        ep_ip,
                    ],
                )?;
            }
            // Unreachable via `setup`, which gates every site on `supports()`
            // first. Kept as a hard error rather than a silent no-op so a
            // future profile added to the vocabulary cannot quietly build a
            // NAT-less site that then "passes" its gate.
            other => {
                return Err(format!(
                    "netns substrate cannot realise NAT profile {other:?}; \
                     supports() must gate this before setup"
                ));
            }
        }
        Ok(())
    }

    /// Remove every `rnsim-*` namespace and interface on the guest, plus the
    /// wan bridge.
    ///
    /// A SWEEP, not a replay of `created_resources`, and deliberately so: an
    /// aborted earlier run (or a crashed guest) leaves residue this handle
    /// never recorded, and residue is release-blocking exactly like exit-NAT
    /// residue. Enumeration failures fail CLOSED — "I could not list the
    /// namespaces" must never read as "there were none". Every removal is
    /// attempted even after one fails, and the failures are reported joined.
    fn sweep(&self, runner: &dyn NetLeafRunner) -> Result<(), String> {
        let mut errors = Vec::new();

        match runner.run(&["ip", "netns", "list"]) {
            Ok(output) if output.success => {
                for name in prefixed_names(&output.stdout, parse_netns_list) {
                    if let Err(err) = validate_netns_name(&name) {
                        errors.push(format!("refusing to delete namespace: {err}"));
                        continue;
                    }
                    match runner.run(&["ip", "netns", "del", &name]) {
                        Err(err) => errors.push(format!("ip netns del {name}: {err}")),
                        Ok(out) if !out.success && !already_gone(&out.stderr) => {
                            errors.push(format!("ip netns del {name}: {}", out.stderr.trim()));
                        }
                        Ok(_) => {}
                    }
                }
            }
            Ok(output) => errors.push(format!("ip netns list failed: {}", output.stderr.trim())),
            Err(err) => errors.push(format!("ip netns list: {err}")),
        }

        match runner.run(&["ip", "-o", "link", "show"]) {
            Ok(output) if output.success => {
                for name in prefixed_names(&output.stdout, parse_ip_link_show) {
                    if let Err(err) = validate_netns_name(&name) {
                        errors.push(format!("refusing to delete interface: {err}"));
                        continue;
                    }
                    match runner.run(&["ip", "link", "del", &name]) {
                        Err(err) => errors.push(format!("ip link del {name}: {err}")),
                        Ok(out) if !out.success && !already_gone(&out.stderr) => {
                            errors.push(format!("ip link del {name}: {}", out.stderr.trim()));
                        }
                        Ok(_) => {}
                    }
                }
            }
            Ok(output) => errors.push(format!("ip -o link show failed: {}", output.stderr.trim())),
            Err(err) => errors.push(format!("ip -o link show: {err}")),
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "netns substrate teardown left possible residue on '{}': {}",
                self.host_alias,
                errors.join("; ")
            ))
        }
    }
}

/// `ip netns del`/`ip link del` on something already gone is the idempotent
/// success case; anything else is potential residue.
fn already_gone(stderr: &str) -> bool {
    let lowered = stderr.to_ascii_lowercase();
    lowered.contains("cannot find device")
        || lowered.contains("no such file or directory")
        || lowered.contains("cannot remove namespace file")
}

/// `rnsim-*` names out of a parsed listing, deduplicated and ordered.
fn prefixed_names(stdout: &str, parse: fn(&str) -> Option<&str>) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    for line in stdout.lines() {
        if let Some(name) = parse(line)
            && name.starts_with(NS_PREFIX)
        {
            seen.insert(name.to_owned());
        }
    }
    seen.into_iter().collect()
}

/// `ip netns list` prints `name (id: 0)` or just `name`.
fn parse_netns_list(line: &str) -> Option<&str> {
    let token = line.split_whitespace().next()?;
    (!token.is_empty()).then_some(token)
}

/// `ip -o link show` prints `3: rnsim-svc-br@if2: <BROADCAST,...> ...`.
fn parse_ip_link_show(line: &str) -> Option<&str> {
    let after_index = line.split_once(": ")?.1;
    let name = after_index.split(':').next()?.trim();
    let name = name.split('@').next()?.trim();
    (!name.is_empty()).then_some(name)
}

impl CrossNetworkSubstrateProvider for NetnsSubstrateProvider {
    fn id(&self) -> &'static str {
        "netns"
    }

    /// The honest per-profile answer for a topology whose every site is ONE
    /// router applying one nftables NAT profile inside a namespace:
    ///
    /// - `port_restricted_cone` — SUPPORTED. Plain `masquerade`: the kernel
    ///   keeps one mapping per source and filters by peer address/port.
    /// - `full_cone` — SUPPORTED. `masquerade` plus a prerouting `dnat` of the
    ///   WireGuard UDP range to the endpoint, which is what makes an
    ///   unsolicited inbound land.
    /// - `symmetric` — SUPPORTED. `masquerade random` re-randomises the source
    ///   port per destination, producing the endpoint-DEPENDENT mapping that
    ///   forces relay fallback.
    /// - `baseline_lan` — REFUSED. It is the no-NAT same-LAN case; every site
    ///   here is defined by having a NAT boundary. Claiming it would report a
    ///   NAT'd topology as the un-NAT'd baseline, i.e. a false pass for the
    ///   one profile whose whole point is the absence of translation.
    /// - `double_nat_cgnat` — SUPPORTED as of CN-4. `build_site` chains a
    ///   carrier namespace (`rnsim-cgn-<name>`) behind the site router over an
    ///   RFC 6598 segment: the home router masquerades the LAN onto
    ///   100.64.x/24 and the carrier masquerades that onto the transit with
    ///   randomised ports, so the endpoint sits behind TWO translations. This
    ///   replaces `netns_internet_sim.sh:189`'s `exit 2` with a built topology
    ///   rather than a typed refusal.
    fn supports(&self, profile: &NatProfileId) -> Support {
        match profile.as_str() {
            "port_restricted_cone" | "full_cone" | "symmetric" | "double_nat_cgnat" => {
                Support::Supported
            }
            "baseline_lan" => Support::UnsupportedByDesign(
                "baseline_lan is the no-NAT same-LAN case and needs no substrate; every netns \
                 site is defined by its NAT boundary"
                    .to_owned(),
            ),
            other => Support::UnsupportedByDesign(format!(
                "{other} is outside the netns simulator's NAT vocabulary"
            )),
        }
    }

    /// The netns simulator realises every profile it claims, but NO modifier.
    ///
    /// uPnP would need `miniupnpd` inside each router namespace and an IGD
    /// client on the far side; the gates this substrate drives are the mapping
    /// and filtering classifiers, whose probes speak STUN, not IGD — a uPnP
    /// claim here would advertise a capability nothing exercises. A routed IPv6
    /// prefix is the same story: the simulated transit is v4-only, so `v6` has
    /// nowhere to route. Both belong to the vxlan tier, where the real daemon
    /// runs on a real guest (spec §8 open question 2).
    fn supports_with_modifiers(&self, profile: &NatProfileId, modifiers: &NatModifiers) -> Support {
        let base = self.supports(profile);
        if !base.is_supported() || modifiers.is_empty() {
            return base;
        }
        Support::UnsupportedModifier {
            modifier: modifiers.describe(),
            reason: "the netns simulator drives the STUN-based mapping and filtering classifiers \
                     over a v4-only simulated transit; uPnP needs an IGD client and a routed IPv6 \
                     prefix needs a v6 transit, neither of which this substrate has — apply \
                     modifiers on the vxlan tier"
                .to_owned(),
        }
    }

    /// Reshaping a netns site in place is deliberately NOT offered.
    ///
    /// Both NAT gates rebuild a clean topology per profile precisely so
    /// conntrack state from the previous profile cannot hide a cold-inbound
    /// result (spec §0.4 CN-2 deviation (b)), and `double_nat_cgnat` is a
    /// different TOPOLOGY — a whole extra namespace and veth pair — not a
    /// different rule set. An in-place reshape would therefore either produce
    /// a verdict contaminated by stale conntrack or silently fail to build the
    /// carrier hop. The typed refusal names `setup` as the supported path
    /// instead of half-applying either.
    fn apply_nat_profile(
        &self,
        _handle: &mut SubstrateHandle,
        site: &SiteRef,
        profile: &NatProfileId,
        _modifiers: &NatModifiers,
        _runners: &BTreeMap<String, &dyn NetLeafRunner>,
    ) -> Result<(), NatApplyError> {
        Err(NatApplyError::Refused(Support::UnsupportedByDesign(
            format!(
                "the netns simulator does not reshape site '{site}' to '{profile}' in place: its \
                 gates rebuild a clean topology per profile so stale conntrack cannot contaminate \
                 a verdict, and double_nat_cgnat is a different topology rather than a different \
                 rule set — rebuild the substrate through setup() with the site's profile instead"
            ),
        )))
    }

    fn setup(
        &self,
        topology: &SubstrateTopology,
        runners: &BTreeMap<String, &dyn NetLeafRunner>,
    ) -> Result<SubstrateHandle, Box<SubstrateSetupFailure>> {
        let fail = |message: String, partial: SubstrateHandle| {
            Box::new(SubstrateSetupFailure { message, partial })
        };
        // Gate every requested profile through `supports()` BEFORE touching
        // the guest: an unsupported profile is a typed refusal, not a
        // half-built topology.
        for site in &self.sites {
            if let Support::UnsupportedByDesign(reason) = self.supports(&site.profile) {
                return Err(fail(
                    format!(
                        "netns substrate cannot realise site '{}' profile '{}': {reason}",
                        site.name, site.profile
                    ),
                    self.empty_handle(topology, false),
                ));
            }
        }
        let raw = match self.runner_for(runners) {
            Ok(runner) => runner,
            Err(err) => return Err(fail(err, self.empty_handle(topology, false))),
        };
        let runner = SudoRunner::new(raw);

        // A stale topology from an aborted run would collide on every name, so
        // sweep first exactly as `netns_internet_sim.sh build` did. A sweep
        // failure here is fatal: building on top of unknown residue is how a
        // gate reports another run's NAT behaviour as this one's.
        let mut handle = self.empty_handle(topology, true);
        if let Err(err) = self.sweep(&runner) {
            return Err(fail(format!("pre-build sweep failed: {err}"), handle));
        }
        if let Err(err) = self.build_wan_core(&runner, &mut handle) {
            return Err(fail(err, handle));
        }
        for (index, site) in self.sites.iter().enumerate() {
            if let Err(err) = self.build_site(&runner, &mut handle, index + 1, site) {
                return Err(fail(
                    format!("site '{}' ({}): {err}", site.name, site.profile),
                    handle,
                ));
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
        let raw = self.runner_for(runners)?;
        self.sweep(&SudoRunner::new(raw))
    }
}

// ───────────────────────── background units ─────────────────────────

/// A background process on the guest, run as a transient systemd unit.
///
/// The shell backgrounded the STUN responders with `&` and killed them by
/// PID. Over an argv-only SSH boundary there is no `&` — and PID-chasing is
/// worse residue hygiene anyway, because a lost PID is an orphaned listener
/// nobody ever reaps. A NAMED transient unit is deterministic: it is stopped
/// by name and `--collect` garbage-collects it, so teardown cannot leak one.
pub struct BackgroundUnit {
    name: String,
}

impl BackgroundUnit {
    /// Names are constructed from constants in this module only, but they are
    /// validated anyway — the check costs nothing and the invariant should not
    /// depend on every future caller remembering it.
    fn validate_name(name: &str) -> Result<(), String> {
        if name.is_empty() || name.len() > 64 {
            return Err(format!("invalid transient unit name {name:?}"));
        }
        if !name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
        {
            return Err(format!(
                "transient unit name must be ASCII letters, digits, '-' or '_': {name:?}"
            ));
        }
        Ok(())
    }

    /// Start `argv` as a transient unit, with stdout captured to `log_path`
    /// on the guest so the caller can read the probe's own verdict line.
    fn start(
        runner: &dyn NetLeafRunner,
        name: &str,
        log_path: &str,
        argv: &[&str],
    ) -> Result<Self, String> {
        Self::validate_name(name)?;
        let unit = format!("{name}.service");
        // A leftover unit from an aborted run would make `systemd-run` fail
        // with "unit already exists"; stopping first is idempotent.
        let _ = runner.run(&["systemctl", "stop", &unit]);
        let stdout_property = format!("StandardOutput=file:{log_path}");
        let mut full: Vec<&str> = vec![
            "systemd-run",
            "--quiet",
            "--collect",
            "--unit",
            name,
            "-p",
            &stdout_property,
            "-p",
            "StandardError=inherit",
            "--",
        ];
        full.extend_from_slice(argv);
        required(runner, &full)?;
        Ok(Self {
            name: name.to_owned(),
        })
    }

    /// Stop the unit. Reported, never ignored: a responder still holding
    /// :3478 would silently corrupt the next profile's verdict.
    fn stop(&self, runner: &dyn NetLeafRunner) -> Result<(), String> {
        let unit = format!("{}.service", self.name);
        match runner.run(&["systemctl", "stop", &unit]) {
            Err(err) => Err(format!("systemctl stop {unit}: {err}")),
            // `--collect` means a unit that already exited is gone; systemctl
            // then reports "not loaded", which is success for our purpose.
            Ok(output) if !output.success && !output.stderr.contains("not loaded") => Err(format!(
                "systemctl stop {unit} failed: {}",
                output.stderr.trim()
            )),
            Ok(_) => Ok(()),
        }
    }

    /// Poll until the unit is no longer active, or the deadline passes.
    fn wait_until_inactive(
        &self,
        runner: &dyn NetLeafRunner,
        timeout: Duration,
        sleep: &dyn Fn(Duration),
    ) -> Result<(), String> {
        let unit = format!("{}.service", self.name);
        let deadline = Instant::now() + timeout;
        loop {
            let output = runner
                .run(&["systemctl", "is-active", &unit])
                .map_err(|err| format!("systemctl is-active {unit}: {err}"))?;
            if output.stdout.trim() != "active" {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!("{unit} still active after {timeout:?}"));
            }
            sleep(Duration::from_millis(200));
        }
    }
}

/// Read a file on the guest, `None` when it is absent or empty.
fn read_remote_file(runner: &dyn NetLeafRunner, path: &str) -> Result<Option<String>, String> {
    let output = runner
        .run(&["cat", path])
        .map_err(|err| format!("cat {path}: {err}"))?;
    if !output.success {
        return Ok(None);
    }
    let text = output.stdout.trim().to_owned();
    Ok((!text.is_empty()).then_some(text))
}

fn remove_remote_file(runner: &dyn NetLeafRunner, path: &str) {
    let _ = runner.run(&["rm", "-f", path]);
}

// ───────────────────────────── the NAT gates ─────────────────────────────

/// One row of gate evidence. Every row is recorded, pass or fail, so the
/// report says WHICH profile misbehaved rather than only that one did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateCheck {
    pub gate: &'static str,
    pub profile: String,
    pub scenario: &'static str,
    pub expected: String,
    pub observed: String,
    pub passed: bool,
}

impl GateCheck {
    pub fn render(&self) -> String {
        format!(
            "{:<10} {:<22} {:<22} expected={:<20} observed={:<20} {}",
            self.gate,
            self.profile,
            self.scenario,
            self.expected,
            self.observed,
            if self.passed { "PASS" } else { "FAIL" }
        )
    }
}

/// The profiles both gates exercise, in the shell scripts' order.
const MAPPING_GATE_PROFILES: &[(&str, &str)] = &[
    ("port_restricted_cone", "endpoint-independent"),
    ("full_cone", "endpoint-independent"),
    ("symmetric", "endpoint-dependent"),
];

const FILTER_GATE_PROFILES: &[&str] = &["full_cone", "port_restricted_cone", "symmetric"];

const FILTER_SCENARIOS: &[&str] = &["RETURN_EXACT", "UNSOLICITED_DIFF_PORT", "COLD_INBOUND"];

const SITE_NAME: &str = "A";
const STUN_PRIMARY_UNIT: &str = "rustynet-rnsim-stun-primary";
const STUN_SECONDARY_UNIT: &str = "rustynet-rnsim-stun-secondary";
const FILTER_INIT_UNIT: &str = "rustynet-rnsim-filter-init";
const FILTER_INIT_LOG: &str = "/tmp/rnsim-filter-init.log";
const FILTER_MAPPED_FILE: &str = "/tmp/rnsim-filter-mapped";
/// Distinct log paths per responder: `StandardOutput=file:` truncates on
/// open, so two units sharing one path would clobber each other's diagnostics.
const STUN_LOG_PRIMARY: &str = "/tmp/rnsim-stun-primary.log";
const STUN_LOG_SECONDARY: &str = "/tmp/rnsim-stun-secondary.log";
const FILTER_LISTEN_SECS: &str = "2";
const DIFF_PORT: u16 = 49378;
const COLD_PORT: u16 = 49379;

/// The expected filtering answer per (profile, scenario) — the §4.1 matrix
/// the gate exists to hold to: a return packet on the exact mapping always
/// lands; anything unsolicited lands ONLY through a full cone.
fn expected_filtering(profile: &str, scenario: &str) -> Result<&'static str, String> {
    match scenario {
        "RETURN_EXACT" => Ok("yes"),
        "UNSOLICITED_DIFF_PORT" | "COLD_INBOUND" => {
            Ok(if profile == "full_cone" { "yes" } else { "no" })
        }
        other => Err(format!("unknown filtering scenario {other:?}")),
    }
}

/// Parse `mapping=<behaviour>` out of the probe's `nat-classify` output.
fn parse_mapping(stdout: &str) -> Option<String> {
    stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix("mapping="))
        .map(|value| value.trim().to_owned())
}

/// Parse `received=(yes|no)` out of the probe's `nat-filter-init` output.
fn parse_received(stdout: &str) -> Option<String> {
    stdout.lines().rev().find_map(|line| {
        line.split_whitespace()
            .find_map(|token| token.strip_prefix("received="))
            .map(str::to_owned)
    })
}

/// A `host:port` string read back off the guest, validated before it can
/// enter argv as a probe `--target`.
fn validated_endpoint(value: &str) -> Result<String, String> {
    value
        .trim()
        .parse::<SocketAddrV4>()
        .map(|addr| addr.to_string())
        .map_err(|_| format!("mapped endpoint {value:?} is not a valid IPv4 host:port"))
}

/// A single-node topology for the guest hosting the simulator. The netns
/// substrate needs no addressing of its own, but the handle records the host's
/// underlay address so the evidence names the guest the residue would be on.
pub fn simulator_topology(alias: &str, host_ip: Ipv4Addr) -> SubstrateTopology {
    SubstrateTopology {
        nodes: BTreeMap::from([(alias.to_owned(), host_ip)]),
    }
}

/// Everything one gate run needs, so the gate functions are pure over their
/// inputs and fully drivable from `MockLeafRunner` in tests.
pub struct NatGateContext<'a> {
    pub host_alias: &'a str,
    pub host_ip: Ipv4Addr,
    /// Injected so tests run at zero wall clock.
    pub sleep: &'a dyn Fn(Duration),
}

/// Both §D5.1 Tier-A gates: NAT mapping behaviour (was
/// `netns_nat_classify.sh`) then NAT filtering behaviour (was
/// `netns_nat_filter.sh`).
///
/// Returns the evidence rows. An `Err` means the gate could not be RUN (the
/// topology would not build, the guest was unreachable); a row with
/// `passed == false` means it ran and the NAT misbehaved. Conflating the two
/// is what made the shell era's exit codes unreadable.
pub fn run_nat_gates(
    raw_runner: &dyn NetLeafRunner,
    ctx: &NatGateContext<'_>,
) -> Result<Vec<GateCheck>, String> {
    let mut checks = run_mapping_gate(raw_runner, ctx)?;
    checks.extend(run_filtering_gate(raw_runner, ctx)?);
    Ok(checks)
}

fn provision_site(
    raw_runner: &dyn NetLeafRunner,
    ctx: &NatGateContext<'_>,
    profile: &str,
) -> Result<(NetnsSubstrateProvider, SubstrateHandle), String> {
    let provider = NetnsSubstrateProvider::single_site(
        ctx.host_alias,
        SITE_NAME,
        NatProfileId::parse(profile)?,
    )?;
    let topology = simulator_topology(ctx.host_alias, ctx.host_ip);
    let runners: BTreeMap<String, &dyn NetLeafRunner> =
        BTreeMap::from([(ctx.host_alias.to_owned(), raw_runner)]);
    match provider.setup(&topology, &runners) {
        Ok(handle) => Ok((provider, handle)),
        Err(failure) => {
            // Fail-closed with cleanup: the partial topology must not survive
            // into the next profile's build, where it would silently answer
            // for the wrong NAT.
            let residue = provider.teardown(&failure.partial, &runners).err();
            Err(match residue {
                Some(residue) => format!(
                    "netns build failed for profile '{profile}': {} (teardown then reported: \
                     {residue})",
                    failure.message
                ),
                None => format!(
                    "netns build failed for profile '{profile}': {}",
                    failure.message
                ),
            })
        }
    }
}

fn release_site(
    raw_runner: &dyn NetLeafRunner,
    ctx: &NatGateContext<'_>,
    provider: &NetnsSubstrateProvider,
    handle: &SubstrateHandle,
) -> Result<(), String> {
    let runners: BTreeMap<String, &dyn NetLeafRunner> =
        BTreeMap::from([(ctx.host_alias.to_owned(), raw_runner)]);
    provider.teardown(handle, &runners)
}

/// NAT mapping-behaviour classification (was `netns_nat_classify.sh`).
fn run_mapping_gate(
    raw_runner: &dyn NetLeafRunner,
    ctx: &NatGateContext<'_>,
) -> Result<Vec<GateCheck>, String> {
    let runner = SudoRunner::new(raw_runner);
    let mut checks = Vec::new();
    for (profile, expected) in MAPPING_GATE_PROFILES {
        let (provider, handle) = provision_site(raw_runner, ctx, profile)?;
        let observed = classify_one_profile(&runner, ctx);
        // Teardown ALWAYS runs, even when the probe itself errored, so a
        // failed measurement never leaves a topology behind.
        let residue = release_site(raw_runner, ctx, &provider, &handle);
        let observed = observed?;
        residue?;
        checks.push(GateCheck {
            gate: "mapping",
            profile: (*profile).to_owned(),
            scenario: "-",
            expected: (*expected).to_owned(),
            observed: observed.clone(),
            passed: observed == *expected,
        });
    }
    Ok(checks)
}

fn classify_one_profile(
    runner: &SudoRunner<'_>,
    ctx: &NatGateContext<'_>,
) -> Result<String, String> {
    let primary_target = format!("{}:{STUN_PORT}", svc_primary());
    let secondary_target = format!("{}:{STUN_PORT}", svc_secondary());
    let primary_port = STUN_PORT.to_string();
    let primary_bind = svc_primary();
    let secondary_bind = svc_secondary();

    let primary = BackgroundUnit::start(
        runner,
        STUN_PRIMARY_UNIT,
        STUN_LOG_PRIMARY,
        &[
            "ip",
            "netns",
            "exec",
            SVC_NS,
            PROBE_BIN,
            "stun-responder",
            "--bind",
            &primary_bind,
            "--port",
            &primary_port,
        ],
    )?;
    let secondary = BackgroundUnit::start(
        runner,
        STUN_SECONDARY_UNIT,
        STUN_LOG_SECONDARY,
        &[
            "ip",
            "netns",
            "exec",
            SVC_NS,
            PROBE_BIN,
            "stun-responder",
            "--bind",
            &secondary_bind,
            "--port",
            &primary_port,
        ],
    )?;
    (ctx.sleep)(Duration::from_secs(1));

    let classify = runner.in_netns(
        &format!("{NS_PREFIX}ep-{SITE_NAME}"),
        &[
            PROBE_BIN,
            "nat-classify",
            "--stun",
            &primary_target,
            "--stun",
            &secondary_target,
        ],
    );
    // Stop both responders regardless of how the probe went.
    let stop_errors: Vec<String> = [primary.stop(runner), secondary.stop(runner)]
        .into_iter()
        .filter_map(Result::err)
        .collect();
    let output = classify.map_err(|err| format!("nat-classify: {err}"))?;
    if !stop_errors.is_empty() {
        return Err(format!(
            "STUN responder teardown failed: {}",
            stop_errors.join("; ")
        ));
    }
    // The probe's own non-zero exit is a measurement failure, not a verdict.
    if !output.success && parse_mapping(&output.stdout).is_none() {
        return Err(format!(
            "nat-classify produced no mapping verdict: {}",
            output.stderr.trim()
        ));
    }
    parse_mapping(&output.stdout).ok_or_else(|| {
        format!(
            "nat-classify output carried no 'mapping=' line: {}",
            output.stdout.trim()
        )
    })
}

/// NAT filtering-behaviour verification (was `netns_nat_filter.sh`).
fn run_filtering_gate(
    raw_runner: &dyn NetLeafRunner,
    ctx: &NatGateContext<'_>,
) -> Result<Vec<GateCheck>, String> {
    let runner = SudoRunner::new(raw_runner);
    let mut checks = Vec::new();
    for profile in FILTER_GATE_PROFILES {
        for scenario in FILTER_SCENARIOS.iter().copied() {
            let expected = expected_filtering(profile, scenario)?;
            let (provider, handle) = provision_site(raw_runner, ctx, profile)?;
            let observed = filter_one_scenario(&runner, ctx, scenario);
            let residue = release_site(raw_runner, ctx, &provider, &handle);
            let observed = observed?;
            residue?;
            checks.push(GateCheck {
                gate: "filtering",
                profile: (*profile).to_owned(),
                scenario,
                expected: expected.to_owned(),
                observed: observed.clone(),
                passed: observed == expected,
            });
        }
    }
    Ok(checks)
}

fn filter_one_scenario(
    runner: &SudoRunner<'_>,
    ctx: &NatGateContext<'_>,
    scenario: &str,
) -> Result<String, String> {
    let ep_ns = format!("{NS_PREFIX}ep-{SITE_NAME}");
    let bind_port = EP_WG_PORT.to_string();
    let stun_target = format!("{}:{STUN_PORT}", svc_primary());
    let stun_port = STUN_PORT.to_string();
    let primary_bind = svc_primary();

    remove_remote_file(runner, FILTER_INIT_LOG);
    remove_remote_file(runner, FILTER_MAPPED_FILE);

    match scenario {
        // The endpoint's own STUN exchange comes back on the exact mapping,
        // so every NAT type must let it through.
        "RETURN_EXACT" => {
            let stun = BackgroundUnit::start(
                runner,
                STUN_PRIMARY_UNIT,
                STUN_LOG_PRIMARY,
                &[
                    "ip",
                    "netns",
                    "exec",
                    SVC_NS,
                    PROBE_BIN,
                    "stun-responder",
                    "--bind",
                    &primary_bind,
                    "--port",
                    &stun_port,
                ],
            )?;
            (ctx.sleep)(Duration::from_millis(400));
            let init = runner.in_netns(
                &ep_ns,
                &[
                    PROBE_BIN,
                    "nat-filter-init",
                    "--bind-port",
                    &bind_port,
                    "--stun",
                    &stun_target,
                    "--mapped-file",
                    FILTER_MAPPED_FILE,
                    "--listen-secs",
                    "0",
                    "--count-stun-response",
                ],
            );
            stun.stop(runner)?;
            let output = init.map_err(|err| format!("nat-filter-init: {err}"))?;
            parse_received(&output.stdout).ok_or_else(|| {
                format!(
                    "nat-filter-init output carried no 'received=' field: {}",
                    output.stdout.trim()
                )
            })
        }
        // An inbound from a DIFFERENT source port to the learned mapping:
        // only a full cone forwards it.
        "UNSOLICITED_DIFF_PORT" => {
            let stun = BackgroundUnit::start(
                runner,
                STUN_PRIMARY_UNIT,
                STUN_LOG_PRIMARY,
                &[
                    "ip",
                    "netns",
                    "exec",
                    SVC_NS,
                    PROBE_BIN,
                    "stun-responder",
                    "--bind",
                    &primary_bind,
                    "--port",
                    &stun_port,
                ],
            )?;
            (ctx.sleep)(Duration::from_millis(400));
            let init = BackgroundUnit::start(
                runner,
                FILTER_INIT_UNIT,
                FILTER_INIT_LOG,
                &[
                    "ip",
                    "netns",
                    "exec",
                    &ep_ns,
                    PROBE_BIN,
                    "nat-filter-init",
                    "--bind-port",
                    &bind_port,
                    "--stun",
                    &stun_target,
                    "--mapped-file",
                    FILTER_MAPPED_FILE,
                    "--listen-secs",
                    FILTER_LISTEN_SECS,
                ],
            )?;
            let mapped = wait_for_mapped_endpoint(runner, ctx)?;
            let probe_bind = format!("{}:{DIFF_PORT}", svc_secondary());
            let probe = runner.in_netns(
                SVC_NS,
                &[
                    PROBE_BIN,
                    "nat-filter-probe",
                    "--bind",
                    &probe_bind,
                    "--target",
                    &mapped,
                ],
            );
            let waited = init.wait_until_inactive(runner, Duration::from_secs(15), ctx.sleep);
            let stops: Vec<String> = [stun.stop(runner), init.stop(runner)]
                .into_iter()
                .filter_map(Result::err)
                .collect();
            probe.map_err(|err| format!("nat-filter-probe: {err}"))?;
            waited?;
            if !stops.is_empty() {
                return Err(format!("background teardown failed: {}", stops.join("; ")));
            }
            read_filter_verdict(runner)
        }
        // A cold inbound straight at the router's WAN address, with no prior
        // outbound at all.
        "COLD_INBOUND" => {
            let init = BackgroundUnit::start(
                runner,
                FILTER_INIT_UNIT,
                FILTER_INIT_LOG,
                &[
                    "ip",
                    "netns",
                    "exec",
                    &ep_ns,
                    PROBE_BIN,
                    "nat-filter-init",
                    "--bind-port",
                    &bind_port,
                    "--listen-secs",
                    FILTER_LISTEN_SECS,
                ],
            )?;
            (ctx.sleep)(Duration::from_millis(300));
            let probe_bind = format!("{}:{COLD_PORT}", svc_secondary());
            let target = format!("{}:{EP_WG_PORT}", site_wan_ip(1));
            let probe = runner.in_netns(
                SVC_NS,
                &[
                    PROBE_BIN,
                    "nat-filter-probe",
                    "--bind",
                    &probe_bind,
                    "--target",
                    &target,
                ],
            );
            let waited = init.wait_until_inactive(runner, Duration::from_secs(15), ctx.sleep);
            let stopped = init.stop(runner);
            probe.map_err(|err| format!("nat-filter-probe: {err}"))?;
            waited?;
            stopped?;
            read_filter_verdict(runner)
        }
        other => Err(format!("unknown filtering scenario {other:?}")),
    }
}

/// Poll for the mapped endpoint the background `nat-filter-init` writes, then
/// validate it before it becomes a probe `--target` argv element.
fn wait_for_mapped_endpoint(
    runner: &SudoRunner<'_>,
    ctx: &NatGateContext<'_>,
) -> Result<String, String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(text) = read_remote_file(runner, FILTER_MAPPED_FILE)? {
            return validated_endpoint(&text);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "nat-filter-init never wrote its mapped endpoint to {FILTER_MAPPED_FILE}"
            ));
        }
        (ctx.sleep)(Duration::from_millis(200));
    }
}

fn read_filter_verdict(runner: &SudoRunner<'_>) -> Result<String, String> {
    let log = read_remote_file(runner, FILTER_INIT_LOG)?
        .ok_or_else(|| format!("nat-filter-init wrote nothing to {FILTER_INIT_LOG}"))?;
    parse_received(&log)
        .ok_or_else(|| format!("nat-filter-init log carried no 'received=' field: {log}"))
}

#[cfg(test)]
#[allow(clippy::too_many_lines)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::stage::cross_network::substrate::ResourceKind;
    use crate::vm_lab::orchestrator::stage::cross_network::substrate::mock::MockLeafRunner;

    fn profile(name: &str) -> NatProfileId {
        NatProfileId::parse(name).expect("known profile")
    }

    fn topology() -> SubstrateTopology {
        simulator_topology("exit-1", "192.168.64.10".parse().expect("ip"))
    }

    fn runners(runner: &MockLeafRunner) -> BTreeMap<String, &dyn NetLeafRunner> {
        BTreeMap::from([("exit-1".to_owned(), runner as &dyn NetLeafRunner)])
    }

    fn provider(profile_name: &str) -> NetnsSubstrateProvider {
        NetnsSubstrateProvider::single_site("exit-1", SITE_NAME, profile(profile_name))
            .expect("provider")
    }

    /// The simulated transit must never overlap the Rustynet mesh overlay
    /// (100.64.0.0/10). This used to be enforced only by
    /// `vm-lab-network-audit` grepping a shell variable; with the value a Rust
    /// constant it is a test.
    #[test]
    fn wan_cidr_does_not_collide_with_the_mesh() {
        let first: u8 = WAN_BASE
            .split('.')
            .next()
            .expect("first octet")
            .parse()
            .expect("numeric");
        assert_ne!(
            first, MESH_OVERLAY_FIRST_OCTET,
            "netns transit {WAN_BASE}.0/24 must not sit inside the mesh 100.64.0.0/10"
        );
        assert_eq!(
            first, 198,
            "transit must stay in the IANA benchmarking range"
        );
    }

    // ── supports(): the honest per-profile answer ──────────────────────

    #[test]
    fn netns_supports_the_three_single_router_profiles_and_the_cgnat_chain() {
        let provider = provider("full_cone");
        for supported in ["port_restricted_cone", "full_cone", "symmetric"] {
            assert_eq!(
                provider.supports(&profile(supported)),
                Support::Supported,
                "{supported} is realisable by one nftables router"
            );
        }
        // CN-4 flipped this one: `build_site` now chains a carrier namespace,
        // so the claim is backed by a topology rather than being a refusal.
        assert_eq!(
            provider.supports(&profile("double_nat_cgnat")),
            Support::Supported,
            "double_nat_cgnat is realisable by the rnsim-cgn-* carrier chain"
        );
    }

    #[test]
    fn netns_refuses_baseline_lan_with_a_reason() {
        let provider = provider("full_cone");
        let baseline = provider.supports(&profile("baseline_lan"));
        assert!(!baseline.is_supported());
        assert!(
            baseline.reason().expect("reason").contains("no-NAT"),
            "baseline_lan refusal must state that it is the un-NAT'd case"
        );
    }

    /// Modifiers are the one thing this substrate claims for NO profile: its
    /// probes speak STUN, not IGD, and its transit is v4-only.
    #[test]
    fn netns_refuses_every_modifier_on_every_supported_profile() {
        let provider = provider("full_cone");
        for supported in [
            "port_restricted_cone",
            "full_cone",
            "symmetric",
            "double_nat_cgnat",
        ] {
            let support = provider
                .supports_with_modifiers(&profile(supported), &NatModifiers::none().with_upnp());
            match support {
                Support::UnsupportedModifier { modifier, reason } => {
                    assert_eq!(modifier, "upnp_available");
                    assert!(reason.contains("IGD client"), "{reason}");
                }
                other => panic!("{supported} must refuse the modifier, got {other:?}"),
            }
        }
        // No modifiers requested is the case every supported profile honours.
        assert_eq!(
            provider.supports_with_modifiers(&profile("full_cone"), &NatModifiers::none()),
            Support::Supported
        );
    }

    /// In-place reshaping is deliberately refused, and the refusal names the
    /// supported path rather than half-applying a rule set over stale
    /// conntrack.
    #[test]
    fn netns_apply_nat_profile_is_a_typed_refusal_naming_setup() {
        let provider = provider("full_cone");
        let runner = MockLeafRunner::default();
        let mut handle = provider.empty_handle(&topology(), true);
        let err = provider
            .apply_nat_profile(
                &mut handle,
                &SiteRef::new(SITE_NAME).expect("site"),
                &profile("symmetric"),
                &NatModifiers::none(),
                &runners(&runner),
            )
            .expect_err("the netns simulator does not reshape in place");
        assert!(matches!(err, NatApplyError::Refused(_)), "{err:?}");
        assert!(
            err.message()
                .contains("rebuild the substrate through setup()"),
            "{err}"
        );
        assert!(runner.recorded().is_empty(), "a refusal must run nothing");
    }

    /// An unsupported profile must be refused BEFORE any leaf command runs —
    /// a half-built topology would otherwise be measured as if it were the
    /// requested one.
    #[test]
    fn setup_refuses_an_unsupported_profile_without_touching_the_guest() {
        let provider = provider("full_cone");
        let unsupported =
            NetnsSubstrateProvider::single_site("exit-1", SITE_NAME, profile("baseline_lan"))
                .expect("provider");
        let runner = MockLeafRunner::default();
        let failure = unsupported
            .setup(&topology(), &runners(&runner))
            .expect_err("unsupported profile must fail closed");
        assert!(failure.message.contains("no-NAT"), "{}", failure.message);
        assert!(
            !failure.partial.record.provisioned,
            "nothing was provisioned"
        );
        assert!(runner.recorded().is_empty(), "no leaf command may run");
        // Sanity: the same provider shape with a supported profile does run.
        assert_eq!(provider.supports(&profile("full_cone")), Support::Supported);
    }

    // ── setup(): the built topology ────────────────────────────────────

    fn recorded_joined(runner: &MockLeafRunner) -> Vec<String> {
        runner
            .recorded()
            .into_iter()
            .map(|argv| argv.join(" "))
            .collect()
    }

    #[test]
    fn setup_builds_the_wan_core_and_one_nat_site() {
        let runner = MockLeafRunner::default();
        let handle = provider("port_restricted_cone")
            .setup(&topology(), &runners(&runner))
            .expect("setup");
        let calls = recorded_joined(&runner);

        // Every leaf op is argv-only and runs through `sudo -n`.
        assert!(
            calls.iter().all(|call| call.starts_with("sudo -n ")),
            "every netns leaf op must be sudo -n prefixed: {calls:?}"
        );
        // The pre-build sweep runs first.
        assert_eq!(calls[0], "sudo -n ip netns list");
        assert!(calls.iter().any(|c| c == "sudo -n ip -o link show"));
        // Core.
        assert!(
            calls
                .iter()
                .any(|c| c == "sudo -n ip link add rnsim-wan type bridge")
        );
        assert!(calls.iter().any(|c| c == "sudo -n ip netns add rnsim-svc"));
        assert!(
            calls.iter().any(|c| c
                == "sudo -n ip netns exec rnsim-svc ip addr add 198.18.0.254/24 dev rnsim-svc-w")
        );
        assert!(
            calls.iter().any(|c| c
                == "sudo -n ip netns exec rnsim-svc ip addr add 198.18.0.253/24 dev rnsim-svc-w")
        );
        // Site A: namespaces, addressing, default route, forwarding.
        assert!(
            calls
                .iter()
                .any(|c| c == "sudo -n ip netns add rnsim-rtr-A")
        );
        assert!(calls.iter().any(|c| c == "sudo -n ip netns add rnsim-ep-A"));
        assert!(
            calls.iter().any(|c| c
                == "sudo -n ip netns exec rnsim-rtr-A ip addr add 198.18.0.11/24 dev rnsim-r1w")
        );
        assert!(calls.iter().any(
            |c| c == "sudo -n ip netns exec rnsim-ep-A ip addr add 10.10.0.2/24 dev rnsim-e1l"
        ));
        assert!(calls.iter().any(|c| c
            == "sudo -n ip netns exec rnsim-ep-A ip route add default via 10.10.0.1"));
        assert!(
            calls
                .iter()
                .any(|c| c == "sudo -n ip netns exec rnsim-rtr-A sysctl -qw net.ipv4.ip_forward=1")
        );
        // port_restricted_cone = plain masquerade, and NOTHING else.
        assert!(calls.iter().any(|c| c
            == "sudo -n ip netns exec rnsim-rtr-A nft add rule ip rnsim_nat post oifname \
                rnsim-r1w masquerade"));
        assert!(
            !calls.iter().any(|c| c.contains("dnat")),
            "a port-restricted cone must not DNAT"
        );
        assert!(
            !calls.iter().any(|c| c.ends_with("masquerade random")),
            "a port-restricted cone must not randomise source ports"
        );

        // The handle records exactly what was created, and NO overlay.
        assert!(handle.record.provisioned);
        assert_eq!(handle.record.substrate_id, "netns");
        assert!(
            handle.overlay_ips.is_empty(),
            "netns provisions no lab-alias overlay address"
        );
        let namespaces: Vec<&str> = handle
            .created_resources
            .iter()
            .filter(|r| r.kind == ResourceKind::Netns)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(namespaces, ["rnsim-svc", "rnsim-rtr-A", "rnsim-ep-A"]);
    }

    #[test]
    fn full_cone_dnats_the_wireguard_udp_range_to_the_endpoint() {
        let runner = MockLeafRunner::default();
        provider("full_cone")
            .setup(&topology(), &runners(&runner))
            .expect("setup");
        let calls = recorded_joined(&runner);
        assert!(calls.iter().any(|c| c
            == "sudo -n ip netns exec rnsim-rtr-A nft add rule ip rnsim_nat pre iifname \
                rnsim-r1w udp dport 51820-51900 dnat to 10.10.0.2"));
    }

    #[test]
    fn symmetric_masquerades_with_random_source_ports() {
        let runner = MockLeafRunner::default();
        provider("symmetric")
            .setup(&topology(), &runners(&runner))
            .expect("setup");
        let calls = recorded_joined(&runner);
        assert!(calls.iter().any(|c| c
            == "sudo -n ip netns exec rnsim-rtr-A nft add rule ip rnsim_nat post oifname \
                rnsim-r1w masquerade random"));
        assert!(
            !calls.iter().any(|c| c.contains("dnat")),
            "symmetric must not DNAT"
        );
    }

    #[test]
    fn a_second_site_gets_its_own_lan_router_and_wan_address() {
        let runner = MockLeafRunner::default();
        let provider = NetnsSubstrateProvider::new(
            "exit-1",
            vec![
                NetnsSite::new("A", profile("full_cone"), NetnsImpairment::None).expect("site"),
                NetnsSite::new("B", profile("symmetric"), NetnsImpairment::Loss5pct).expect("site"),
            ],
        )
        .expect("provider");
        provider
            .setup(&topology(), &runners(&runner))
            .expect("setup");
        let calls = recorded_joined(&runner);
        assert!(
            calls.iter().any(|c| c
                == "sudo -n ip netns exec rnsim-rtr-B ip addr add 198.18.0.12/24 dev rnsim-r2w")
        );
        assert!(calls.iter().any(
            |c| c == "sudo -n ip netns exec rnsim-ep-B ip addr add 10.20.0.2/24 dev rnsim-e2l"
        ));
        assert!(calls.iter().any(|c| c
            == "sudo -n ip netns exec rnsim-ep-B tc qdisc add dev rnsim-e2l root netem loss 5%"));
    }

    /// The CN-4 CGNAT chain, and the property that makes it that rather than a
    /// relabelled single NAT: TWO translation hops are visible in the rule set,
    /// in two DIFFERENT namespaces, with RFC 6598 space between them.
    #[test]
    fn double_nat_cgnat_builds_two_translation_hops_in_a_carrier_chain() {
        let runner = MockLeafRunner::default();
        let cgnat_provider =
            NetnsSubstrateProvider::single_site("exit-1", SITE_NAME, profile("double_nat_cgnat"))
                .expect("provider");
        let handle = cgnat_provider
            .setup(&topology(), &runners(&runner))
            .expect("setup");
        let calls = recorded_joined(&runner);

        // Both routers exist, and the carrier is a namespace of its own.
        assert!(
            handle
                .created_resources
                .contains(&CreatedResource::netns("exit-1", "rnsim-cgn-A")),
            "{:?}",
            handle.created_resources
        );

        // Hop 1 (home router): plain masquerade onto the carrier segment.
        assert!(
            calls.iter().any(|c| c
                == "sudo -n ip netns exec rnsim-rtr-A nft add rule ip rnsim_nat post oifname \
                    rnsim-h1c masquerade"),
            "{calls:#?}"
        );
        // Hop 2 (carrier): port-randomising masquerade onto the transit. No
        // uPnP is offered here, matching real CGNAT deployments.
        assert!(
            calls.iter().any(|c| c
                == "sudo -n ip netns exec rnsim-cgn-A nft add rule ip rnsim_nat post oifname \
                    rnsim-r1w masquerade random"),
            "{calls:#?}"
        );

        // Exactly two translation hops, one per namespace — a third would mean
        // a rule leaked into the wrong namespace.
        let mut masquerade_namespaces: Vec<&str> = calls
            .iter()
            .filter(|c| c.contains("masquerade"))
            .map(|c| {
                c.split_whitespace()
                    .nth(5)
                    .expect("ip netns exec <ns> is the argv prefix")
            })
            .collect();
        assert_eq!(
            masquerade_namespaces.len(),
            2,
            "exactly two translation hops: {calls:#?}"
        );
        masquerade_namespaces.sort_unstable();
        assert_eq!(
            masquerade_namespaces,
            ["rnsim-cgn-A", "rnsim-rtr-A"],
            "one hop per namespace, carrier and home: {calls:#?}"
        );

        // The segment between them is RFC 6598 shared space — the address the
        // daemon's CGNAT detection reads.
        assert!(
            calls.iter().any(|c| c
                == "sudo -n ip netns exec rnsim-rtr-A ip addr add 100.64.201.2/24 dev rnsim-h1c")
                && calls.iter().any(|c| c
                    == "sudo -n ip netns exec rnsim-cgn-A ip addr add 100.64.201.1/24 dev \
                        rnsim-c1h"),
            "{calls:#?}"
        );
        assert!(
            cgn_base(1).starts_with("100.64."),
            "the carrier segment must be RFC 6598 shared address space, or CGNAT detection has \
             nothing to detect"
        );

        // The site's WAN address is on the CARRIER, not the home router: the
        // home router's only way out is the carrier.
        assert!(
            calls.iter().any(|c| c
                == "sudo -n ip netns exec rnsim-cgn-A ip addr add 198.18.0.11/24 dev rnsim-r1w"),
            "{calls:#?}"
        );
        assert!(
            calls
                .iter()
                .any(|c| c
                    == "sudo -n ip netns exec rnsim-rtr-A ip route add default via 100.64.201.1"),
            "{calls:#?}"
        );
        // And a single-hop profile keeps building exactly one namespace pair.
        let single = MockLeafRunner::default();
        let single_handle = provider("port_restricted_cone")
            .setup(&topology(), &runners(&single))
            .expect("setup");
        assert!(
            !single_handle
                .created_resources
                .iter()
                .any(|resource| resource.name.starts_with("rnsim-cgn-")),
            "a single-router profile must not build a carrier namespace"
        );
    }

    /// Both hops are swept by the same `rnsim-*` prefix teardown — a carrier
    /// namespace left behind is residue exactly like a router one.
    #[test]
    fn teardown_sweeps_the_carrier_namespace_too() {
        let runner = MockLeafRunner {
            stdout_by_match: vec![
                (
                    "ip netns list".to_owned(),
                    "rnsim-rtr-A\nrnsim-cgn-A\nrnsim-ep-A\nrnsim-svc\nunrelated-ns\n".to_owned(),
                ),
                (
                    "ip -o link show".to_owned(),
                    "1: lo: <LOOPBACK>\n2: rnsim-wan: <BROADCAST>\n3: rnsim-h1c@if4: \
                     <BROADCAST>\n"
                        .to_owned(),
                ),
            ],
            ..MockLeafRunner::default()
        };
        let provider =
            NetnsSubstrateProvider::single_site("exit-1", SITE_NAME, profile("double_nat_cgnat"))
                .expect("provider");
        let handle = provider.empty_handle(&topology(), true);
        provider
            .teardown(&handle, &runners(&runner))
            .expect("teardown");
        let calls = recorded_joined(&runner);
        assert!(
            calls.contains(&"sudo -n ip netns del rnsim-cgn-A".to_owned()),
            "{calls:#?}"
        );
        assert!(
            calls.contains(&"sudo -n ip link del rnsim-h1c".to_owned()),
            "{calls:#?}"
        );
        assert!(
            !calls.iter().any(|c| c.contains("unrelated-ns")),
            "the sweep is prefix-scoped: {calls:#?}"
        );
    }

    // ── setup() failure paths ──────────────────────────────────────────

    /// A leaf command failing mid-provision must (a) fail the setup, (b) keep
    /// every resource created before the failure on the partial handle, and
    /// (c) leave that partial handle teardown-able.
    #[test]
    fn a_failure_mid_provision_keeps_the_partial_state_for_teardown() {
        // Sweep is calls 0..=1 (netns list, link show). Core starts at 2:
        // link add bridge (2), link set up (3), netns add svc (4) → fail there.
        let runner = MockLeafRunner {
            fail_on: vec![4],
            failure_stderr: "Cannot create namespace file: File exists".to_owned(),
            ..MockLeafRunner::default()
        };
        let failure = provider("full_cone")
            .setup(&topology(), &runners(&runner))
            .expect_err("a failed leaf command must fail the setup");
        assert!(failure.message.contains("netns"), "{}", failure.message);
        assert!(
            failure.partial.record.provisioned,
            "a partial build is provisioned state that must be torn down"
        );
        assert_eq!(
            failure
                .partial
                .created_resources
                .iter()
                .map(|r| r.name.as_str())
                .collect::<Vec<_>>(),
            ["rnsim-wan"],
            "only the bridge had been created when the failure hit"
        );

        // Teardown of that partial handle is still attempted and succeeds.
        let td = MockLeafRunner {
            stdout_for: vec![
                (0, "rnsim-svc (id: 0)\nrnsim-rtr-A (id: 1)\n".to_owned()),
                (
                    3,
                    "1: lo: <LOOPBACK>\n2: rnsim-wan: <BROADCAST>\n".to_owned(),
                ),
            ],
            ..MockLeafRunner::default()
        };
        provider("full_cone")
            .teardown(&failure.partial, &runners(&td))
            .expect("partial teardown");
        let calls = recorded_joined(&td);
        assert!(calls.iter().any(|c| c == "sudo -n ip netns del rnsim-svc"));
        assert!(
            calls
                .iter()
                .any(|c| c == "sudo -n ip netns del rnsim-rtr-A")
        );
        assert!(calls.iter().any(|c| c == "sudo -n ip link del rnsim-wan"));
    }

    /// A transport failure (guest unreachable) mid-provision is also fatal,
    /// and equally keeps the partial state.
    #[test]
    fn a_transport_failure_mid_provision_fails_closed() {
        let runner = MockLeafRunner {
            transport_error_on: vec![5],
            ..MockLeafRunner::default()
        };
        let failure = provider("full_cone")
            .setup(&topology(), &runners(&runner))
            .expect_err("an unreachable guest must fail the setup");
        assert!(
            failure.message.contains("mock transport failure"),
            "{}",
            failure.message
        );
    }

    /// The pre-build sweep failing is fatal: building on unknown residue is
    /// how one run's NAT behaviour gets reported as another's.
    #[test]
    fn a_failed_pre_build_sweep_aborts_before_building_anything() {
        let runner = MockLeafRunner {
            fail_on: vec![0],
            failure_stderr: "Operation not permitted".to_owned(),
            ..MockLeafRunner::default()
        };
        let failure = provider("full_cone")
            .setup(&topology(), &runners(&runner))
            .expect_err("a failed sweep must abort the build");
        assert!(
            failure.message.contains("pre-build sweep failed"),
            "{}",
            failure.message
        );
        assert!(
            !recorded_joined(&runner)
                .iter()
                .any(|c| c.contains("link add")),
            "nothing may be built after a failed sweep"
        );
    }

    #[test]
    fn setup_without_a_runner_for_the_host_fails_closed() {
        let other = MockLeafRunner::default();
        let runners: BTreeMap<String, &dyn NetLeafRunner> =
            BTreeMap::from([("someone-else".to_owned(), &other as &dyn NetLeafRunner)]);
        let failure = provider("full_cone")
            .setup(&topology(), &runners)
            .expect_err("no runner for the netns host must fail closed");
        assert!(
            failure.message.contains("no leaf runner"),
            "{}",
            failure.message
        );
        assert!(other.recorded().is_empty());
    }

    // ── teardown() ─────────────────────────────────────────────────────

    #[test]
    fn teardown_sweeps_every_prefixed_namespace_and_interface() {
        let runner = MockLeafRunner {
            stdout_for: vec![
                (
                    0,
                    "rnsim-svc (id: 0)\nrnsim-rtr-A (id: 1)\nunrelated-ns\n".to_owned(),
                ),
                (
                    3,
                    "1: lo: <LOOPBACK>\n2: eth0: <BROADCAST>\n3: rnsim-wan: <BROADCAST>\n\
                     4: rnsim-r1br@if5: <BROADCAST>\n"
                        .to_owned(),
                ),
            ],
            ..MockLeafRunner::default()
        };
        let handle = provider("full_cone").empty_handle(&topology(), true);
        provider("full_cone")
            .teardown(&handle, &runners(&runner))
            .expect("teardown");
        let calls = recorded_joined(&runner);
        assert!(calls.iter().any(|c| c == "sudo -n ip netns del rnsim-svc"));
        assert!(
            calls
                .iter()
                .any(|c| c == "sudo -n ip netns del rnsim-rtr-A")
        );
        assert!(
            !calls.iter().any(|c| c.contains("unrelated-ns")),
            "teardown must touch only rnsim-* names"
        );
        assert!(calls.iter().any(|c| c == "sudo -n ip link del rnsim-wan"));
        assert!(calls.iter().any(|c| c == "sudo -n ip link del rnsim-r1br"));
        assert!(
            !calls.iter().any(|c| c.contains("link del eth0")),
            "teardown must never touch the guest's real interfaces"
        );
    }

    /// Already-gone is idempotent success; a real removal failure is residue
    /// and must FAIL the teardown — while every other removal is still tried.
    #[test]
    fn teardown_tolerates_already_gone_but_reports_real_failures() {
        let runner = MockLeafRunner {
            stdout_for: vec![
                (0, "rnsim-svc\nrnsim-rtr-A\n".to_owned()),
                (3, "2: rnsim-wan: <BROADCAST>\n".to_owned()),
            ],
            fail_on: vec![1],
            failure_stderr: "Cannot remove namespace file \"/var/run/netns/rnsim-svc\": No such \
                             file or directory"
                .to_owned(),
            ..MockLeafRunner::default()
        };
        let handle = provider("full_cone").empty_handle(&topology(), true);
        provider("full_cone")
            .teardown(&handle, &runners(&runner))
            .expect("already-gone is idempotent success");

        let broken = MockLeafRunner {
            stdout_for: vec![
                (0, "rnsim-svc\nrnsim-rtr-A\n".to_owned()),
                (3, "2: rnsim-wan: <BROADCAST>\n".to_owned()),
            ],
            fail_on: vec![1],
            failure_stderr: "RTNETLINK answers: Operation not permitted".to_owned(),
            ..MockLeafRunner::default()
        };
        let err = provider("full_cone")
            .teardown(&handle, &runners(&broken))
            .expect_err("a real removal failure is residue");
        assert!(err.contains("possible residue"), "{err}");
        let calls = recorded_joined(&broken);
        assert!(
            calls
                .iter()
                .any(|c| c == "sudo -n ip netns del rnsim-rtr-A"),
            "every other removal must still be attempted: {calls:?}"
        );
    }

    /// Enumeration failing must NOT read as "there was no residue".
    #[test]
    fn teardown_fails_closed_when_it_cannot_enumerate() {
        let runner = MockLeafRunner {
            transport_error_on: vec![0],
            ..MockLeafRunner::default()
        };
        let handle = provider("full_cone").empty_handle(&topology(), true);
        let err = provider("full_cone")
            .teardown(&handle, &runners(&runner))
            .expect_err("an unlistable guest must fail the teardown");
        assert!(err.contains("ip netns list"), "{err}");
    }

    #[test]
    fn teardown_of_an_unprovisioned_handle_is_a_no_op() {
        let runner = MockLeafRunner::default();
        let handle = provider("full_cone").empty_handle(&topology(), false);
        provider("full_cone")
            .teardown(&handle, &runners(&runner))
            .expect("no-op teardown");
        assert!(runner.recorded().is_empty());
    }

    // ── constructor validation ─────────────────────────────────────────

    #[test]
    fn site_names_are_allowlisted_before_they_can_reach_argv() {
        for hostile in ["", "a b", "a;reboot", "../x", "a$(id)", "a\nb", "-rf"] {
            assert!(
                NetnsSite::new(hostile, profile("full_cone"), NetnsImpairment::None).is_err(),
                "{hostile:?} must be rejected as a site name"
            );
        }
        assert!(NetnsSite::new("A", profile("full_cone"), NetnsImpairment::None).is_ok());
        assert!(NetnsSite::new("site_1-b", profile("symmetric"), NetnsImpairment::None).is_ok());
    }

    #[test]
    fn provider_rejects_empty_duplicate_and_oversized_site_lists() {
        assert!(NetnsSubstrateProvider::new("exit-1", Vec::new()).is_err());
        assert!(NetnsSubstrateProvider::single_site("", SITE_NAME, profile("full_cone")).is_err());
        let dup = vec![
            NetnsSite::new("A", profile("full_cone"), NetnsImpairment::None).expect("site"),
            NetnsSite::new("A", profile("symmetric"), NetnsImpairment::None).expect("site"),
        ];
        assert!(NetnsSubstrateProvider::new("exit-1", dup).is_err());
        let many: Vec<NetnsSite> = (0..=MAX_SITES)
            .map(|i| {
                NetnsSite::new(
                    &format!("s{i}"),
                    profile("full_cone"),
                    NetnsImpairment::None,
                )
                .expect("site")
            })
            .collect();
        assert!(NetnsSubstrateProvider::new("exit-1", many).is_err());
    }

    #[test]
    fn impairment_parsing_is_a_closed_set() {
        assert_eq!(
            NetnsImpairment::parse("none").expect("none"),
            NetnsImpairment::None
        );
        assert_eq!(
            NetnsImpairment::parse("loss_5pct").expect("loss"),
            NetnsImpairment::Loss5pct
        );
        assert!(NetnsImpairment::parse("delay 50ms; reboot").is_err());
        assert!(NetnsImpairment::parse("netem").is_err());
    }

    // ── parsers and validators ─────────────────────────────────────────

    #[test]
    fn listing_parsers_extract_only_prefixed_names() {
        assert_eq!(parse_netns_list("rnsim-svc (id: 0)"), Some("rnsim-svc"));
        assert_eq!(
            parse_ip_link_show("4: rnsim-r1br@if5: <BROADCAST>"),
            Some("rnsim-r1br")
        );
        assert_eq!(parse_ip_link_show("1: lo: <LOOPBACK>"), Some("lo"));
        assert_eq!(
            prefixed_names("rnsim-b\nrnsim-a\nother\n", parse_netns_list),
            ["rnsim-a", "rnsim-b"],
            "deduplicated and ordered"
        );
    }

    /// A hostile name in the guest's own listing must be refused, not deleted.
    #[test]
    fn sweep_refuses_a_hostile_name_from_the_guest_listing() {
        let runner = MockLeafRunner {
            stdout_for: vec![
                (0, "rnsim-../../etc\nrnsim-ok\n".to_owned()),
                (2, String::new()),
            ],
            ..MockLeafRunner::default()
        };
        let handle = provider("full_cone").empty_handle(&topology(), true);
        let err = provider("full_cone")
            .teardown(&handle, &runners(&runner))
            .expect_err("a path-bearing name must be refused");
        assert!(err.contains("refusing to delete namespace"), "{err}");
        let calls = recorded_joined(&runner);
        assert!(
            !calls.iter().any(|c| c.contains("etc")),
            "the hostile name must never enter argv: {calls:?}"
        );
        assert!(
            calls.iter().any(|c| c == "sudo -n ip netns del rnsim-ok"),
            "the legitimate name is still removed"
        );
    }

    #[test]
    fn probe_output_parsers_read_the_verdict_lines() {
        assert_eq!(
            parse_mapping("reflexive=1.2.3.4:5\nmapping=endpoint-independent\n").as_deref(),
            Some("endpoint-independent")
        );
        assert_eq!(parse_mapping("no verdict here"), None);
        assert_eq!(
            parse_received("mapped=1.2.3.4:5 received=yes from=6.7.8.9:1 detail=udp_probe")
                .as_deref(),
            Some("yes")
        );
        assert_eq!(
            parse_received("mapped=1.2.3.4:5 received=no from= detail=none").as_deref(),
            Some("no")
        );
        assert_eq!(parse_received("nothing"), None);
    }

    #[test]
    fn a_mapped_endpoint_read_off_the_guest_is_validated_before_use() {
        assert_eq!(
            validated_endpoint(" 198.18.0.11:51820\n").expect("valid"),
            "198.18.0.11:51820"
        );
        for hostile in [
            "",
            "not-an-endpoint",
            "1.2.3.4",
            "$(id)",
            "1.2.3.4:51820 extra",
        ] {
            assert!(
                validated_endpoint(hostile).is_err(),
                "{hostile:?} must be refused as a probe target"
            );
        }
    }

    #[test]
    fn the_filtering_matrix_only_lets_a_full_cone_take_unsolicited_inbound() {
        assert_eq!(
            expected_filtering("symmetric", "RETURN_EXACT").expect("row"),
            "yes"
        );
        assert_eq!(
            expected_filtering("full_cone", "COLD_INBOUND").expect("row"),
            "yes"
        );
        assert_eq!(
            expected_filtering("port_restricted_cone", "COLD_INBOUND").expect("row"),
            "no"
        );
        assert_eq!(
            expected_filtering("symmetric", "UNSOLICITED_DIFF_PORT").expect("row"),
            "no"
        );
        assert!(expected_filtering("full_cone", "MADE_UP").is_err());
    }

    // ── background units ───────────────────────────────────────────────

    #[test]
    fn a_background_unit_is_a_named_collected_transient_unit() {
        let raw = MockLeafRunner::default();
        let runner = SudoRunner::new(&raw);
        let unit = BackgroundUnit::start(
            &runner,
            STUN_PRIMARY_UNIT,
            STUN_LOG_PRIMARY,
            &["ip", "netns", "exec", SVC_NS, PROBE_BIN, "stun-responder"],
        )
        .expect("start");
        let calls = recorded_joined(&raw);
        assert_eq!(
            calls[0],
            format!("sudo -n systemctl stop {STUN_PRIMARY_UNIT}.service"),
            "a leftover unit is stopped first"
        );
        assert_eq!(
            calls[1],
            format!(
                "sudo -n systemd-run --quiet --collect --unit {STUN_PRIMARY_UNIT} -p \
                 StandardOutput=file:{STUN_LOG_PRIMARY} -p StandardError=inherit -- ip netns exec \
                 rnsim-svc {PROBE_BIN} stun-responder"
            )
        );
        unit.stop(&runner).expect("stop");
        assert_eq!(
            recorded_joined(&raw).last().expect("stop call"),
            &format!("sudo -n systemctl stop {STUN_PRIMARY_UNIT}.service")
        );
    }

    #[test]
    fn background_unit_names_are_validated() {
        for hostile in ["", "a b", "a;b", "../x", &"a".repeat(65)] {
            assert!(
                BackgroundUnit::validate_name(hostile).is_err(),
                "{hostile:?}"
            );
        }
        assert!(BackgroundUnit::validate_name(STUN_PRIMARY_UNIT).is_ok());
    }

    #[test]
    fn stopping_a_unit_that_already_exited_is_success_but_a_real_failure_is_not() {
        let gone = MockLeafRunner {
            fail_on: vec![0],
            failure_stderr: "Failed to stop x.service: Unit x.service not loaded.".to_owned(),
            ..MockLeafRunner::default()
        };
        let runner = SudoRunner::new(&gone);
        BackgroundUnit {
            name: STUN_PRIMARY_UNIT.to_owned(),
        }
        .stop(&runner)
        .expect("a collected unit is already gone");

        let broken = MockLeafRunner {
            fail_on: vec![0],
            failure_stderr: "Interactive authentication required.".to_owned(),
            ..MockLeafRunner::default()
        };
        let runner = SudoRunner::new(&broken);
        assert!(
            BackgroundUnit {
                name: STUN_PRIMARY_UNIT.to_owned(),
            }
            .stop(&runner)
            .is_err(),
            "a responder we could not stop would corrupt the next profile"
        );
    }

    // ── the gates, end to end against the mock ─────────────────────────

    fn no_sleep() -> impl Fn(Duration) {
        |_| {}
    }

    fn gate_ctx<'a>(sleep: &'a dyn Fn(Duration)) -> NatGateContext<'a> {
        NatGateContext {
            host_alias: "exit-1",
            host_ip: "192.168.64.10".parse().expect("ip"),
            sleep,
        }
    }

    /// A runner that answers every enumeration with an empty listing, every
    /// `cat` with a scripted body, and every `nat-classify`/`nat-filter-init`
    /// with a scripted verdict — enough to drive both gates deterministically.
    fn scripted_runner(mapping: &str, received: &str) -> MockLeafRunner {
        MockLeafRunner {
            stdout_by_match: vec![
                ("nat-classify".to_owned(), format!("mapping={mapping}\n")),
                (
                    "cat /tmp/rnsim-filter-mapped".to_owned(),
                    "198.18.0.11:51820\n".to_owned(),
                ),
                (
                    "cat /tmp/rnsim-filter-init.log".to_owned(),
                    format!("mapped=198.18.0.11:51820 received={received} detail=udp_probe\n"),
                ),
                (
                    "nat-filter-init".to_owned(),
                    format!("mapped=198.18.0.11:51820 received={received} detail=stun_response\n"),
                ),
                ("systemctl is-active".to_owned(), "inactive\n".to_owned()),
            ],
            ..MockLeafRunner::default()
        }
    }

    #[test]
    fn the_mapping_gate_records_a_row_per_profile_and_flags_the_misbehaving_one() {
        let sleep = no_sleep();
        let ctx = gate_ctx(&sleep);
        // Every profile reports endpoint-independent: correct for the two cone
        // profiles, WRONG for symmetric — which must be flagged, not hidden.
        let runner = scripted_runner("endpoint-independent", "yes");
        let checks = run_mapping_gate(&runner, &ctx).expect("gate runs");
        assert_eq!(checks.len(), 3);
        assert_eq!(
            checks
                .iter()
                .map(|c| (c.profile.as_str(), c.passed))
                .collect::<Vec<_>>(),
            [
                ("port_restricted_cone", true),
                ("full_cone", true),
                ("symmetric", false)
            ]
        );
        assert_eq!(checks[2].expected, "endpoint-dependent");
        assert!(checks[2].render().ends_with("FAIL"));
    }

    #[test]
    fn the_filtering_gate_covers_three_profiles_by_three_scenarios() {
        let sleep = no_sleep();
        let ctx = gate_ctx(&sleep);
        let runner = scripted_runner("endpoint-independent", "yes");
        let checks = run_filtering_gate(&runner, &ctx).expect("gate runs");
        assert_eq!(checks.len(), 9);
        // "received=yes" everywhere: right for a full cone, wrong for the
        // other two on the unsolicited scenarios.
        let failing: Vec<(&str, &str)> = checks
            .iter()
            .filter(|c| !c.passed)
            .map(|c| (c.profile.as_str(), c.scenario))
            .collect();
        assert_eq!(
            failing,
            [
                ("port_restricted_cone", "UNSOLICITED_DIFF_PORT"),
                ("port_restricted_cone", "COLD_INBOUND"),
                ("symmetric", "UNSOLICITED_DIFF_PORT"),
                ("symmetric", "COLD_INBOUND"),
            ]
        );
    }

    /// A build failure inside a gate is an Err (the gate could not RUN), never
    /// a silent `false` row that would read as "the NAT misbehaved".
    #[test]
    fn a_gate_reports_a_build_failure_as_an_error_not_as_a_failing_row() {
        let sleep = no_sleep();
        let ctx = gate_ctx(&sleep);
        let runner = MockLeafRunner {
            fail_on: vec![2],
            failure_stderr: "RTNETLINK answers: Operation not permitted".to_owned(),
            ..MockLeafRunner::default()
        };
        let err = run_mapping_gate(&runner, &ctx).expect_err("a build failure is an error");
        assert!(err.contains("netns build failed"), "{err}");
    }

    /// The topology is torn down after EVERY profile, so one profile's NAT can
    /// never answer for the next.
    #[test]
    fn each_gate_profile_tears_its_topology_down_before_the_next_builds() {
        let sleep = no_sleep();
        let ctx = gate_ctx(&sleep);
        let runner = scripted_runner("endpoint-independent", "yes");
        run_mapping_gate(&runner, &ctx).expect("gate runs");
        let calls = recorded_joined(&runner);
        let builds = calls
            .iter()
            .filter(|c| *c == "sudo -n ip link add rnsim-wan type bridge")
            .count();
        // One pre-build sweep + one teardown sweep per profile, three profiles.
        let sweeps = calls
            .iter()
            .filter(|c| *c == "sudo -n ip netns list")
            .count();
        assert_eq!(builds, 3, "one build per profile");
        assert_eq!(sweeps, 6, "a pre-build sweep and a teardown sweep each");
    }

    #[test]
    fn the_gate_runs_both_halves_in_order() {
        let sleep = no_sleep();
        let ctx = gate_ctx(&sleep);
        let runner = scripted_runner("endpoint-independent", "no");
        let checks = run_nat_gates(&runner, &ctx).expect("gates run");
        assert_eq!(checks.len(), 12);
        assert_eq!(checks[0].gate, "mapping");
        assert_eq!(checks[3].gate, "filtering");
    }
}
