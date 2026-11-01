//! Moving a node's underlay endpoint out from under a live tunnel.
//!
//! Two scenarios need an alias on the underlay: node-network-switch moves the
//! *client* onto a new underlay address to prove endpoint-change detection and
//! re-convergence, and failback-roaming adds an alias on the *exit* to prove the
//! roam is recovered from. The shared primitives live here.
//!
//! # The node-switch stimulus is a source pin, not a default-route edit
//!
//! The first port (and the bash original) added an IP alias to the default-route
//! interface and ran `ip route replace default dev <if> src <alias>`. That is not
//! a network switch, and the katana vxlan runs proved it:
//!
//! * with no `via` and no metric the replace does not replace the DHCP default
//!   route (`... via 192.168.122.1 ... metric 100`), it adds a second on-link
//!   default at metric 0, so the gateway the daemon fingerprints never moved;
//! * and WireGuard traffic never used the main-table default at all. The daemon's
//!   full-tunnel policy routing sends everything through `ip rule 10000 lookup
//!   51820`, whose bypass pin for the exit's underlay address carries a `via` but
//!   no `src`. The kernel then picks the *primary* address of the interface, so
//!   the peer kept seeing the old source and no roam ever happened.
//!
//! The stimulus is therefore a **source pin**: a real new address on the underlay
//! interface plus a private routing table and a policy rule, ahead of the
//! daemon's, that makes the kernel use that address as the source of the
//! WireGuard flow (UDP to the exit's WireGuard port) to the exit. The rule is
//! narrowed to that flow on purpose: the guest also sends other traffic to the
//! exit's underlay address - the vxlan substrate's outer UDP/4789 frames go to
//! the very same address - and re-sourcing those would perturb the lab
//! substrate instead of testing the tunnel. It needs the `ipproto`/`dport`
//! rule selectors (iproute2 and kernel 4.17 or newer); an older guest fails the
//! apply by name rather than silently pinning more than intended.
//!
//! The daemon's own table 51820 is never edited (its apply path self-checks
//! those pins). The old address is deliberately left in place: the orchestrator
//! reaches the guest over it, and removing it would cut the control channel to
//! the node under test.
//!
//! # Rollback removes what was added, and says so when it cannot
//!
//! The old teardown read the guest's own `ip -4 route show default` back and fed
//! every line to `ip route replace` (token-filtered) under a swallow-everything
//! `|| true`. The pin replays nothing the guest said: it records which of the
//! three things it installed (address, route, rule) actually succeeded, removes
//! exactly those in reverse order, then READS BACK to prove they are gone. A
//! rollback that cannot prove it is a stage failure carrying the exact cleanup
//! commands, because residue on a lab guest is the next stage's problem.

use std::net::Ipv4Addr;
use std::time::Duration;

use super::super::substrate::NetLeafRunner;
use super::provisioning::{self, validate_argv_value};
use super::{capture_root_allow_failure, run_root, run_root_allow_failure};

/// A spare underlay address the client can be moved onto, as
/// `ops choose-cross-network-roam-alias` picks it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoamAlias {
    pub ip: String,
    pub prefix: u8,
}

impl RoamAlias {
    /// `ip/prefix`, the spelling `ip addr add` and `ip addr del` take.
    pub fn cidr(&self) -> String {
        format!("{}/{}", self.ip, self.prefix)
    }

    /// `alias:51820` — what a peer's `wg show … endpoints` prints once the roam
    /// has been observed.
    pub fn wireguard_endpoint(&self) -> String {
        format!("{}:{}", self.ip, super::WIREGUARD_PORT)
    }
}

/// Choose an alias on the client's own prefix that collides with neither
/// endpoint already in play.
///
/// `used` is the addresses the alias must avoid; the shell passed the client's
/// and the exit's, and passing fewer would let the alias land on a node already
/// in the topology.
pub fn choose_alias(client_address: &str, used: &[&str]) -> Result<RoamAlias, String> {
    let (ip, prefix) = provisioning::choose_cross_network_roam_alias(client_address, used)?;
    Ok(RoamAlias { ip, prefix })
}

/// The node's default route as it was before the switch: which interface
/// carries it, and the whole `ip -4 route show default` text (kept for the
/// operator-facing transcript; nothing replays it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultRoute {
    pub iface: String,
    pub snapshot: String,
}

/// Read the node's default route.
///
/// Fails closed when no default route names an interface: every later step
/// (`ip addr add … dev`, the route pin's `dev`) needs that name, and guessing
/// one would move an address onto the wrong link.
pub fn read_default_route(runner: &dyn NetLeafRunner) -> Result<DefaultRoute, String> {
    let snapshot =
        provisioning::capture_allow_failure(runner, &["ip", "-4", "route", "show", "default"])?;
    let iface = parse_default_route_iface(&snapshot)
        .ok_or_else(|| "failed to resolve client default underlay interface".to_owned())?;
    validate_argv_value("default route interface", &iface)?;
    Ok(DefaultRoute { iface, snapshot })
}

/// The interface the first `default …` line routes out of.
///
/// "First wins" matches the shell's `awk '/^default/ { …; exit }'`: a second
/// default route must not be able to override the one actually in use.
pub fn parse_default_route_iface(route_output: &str) -> Option<String> {
    route_output
        .lines()
        .find(|line| line.starts_with("default"))
        .and_then(|line| {
            let mut tokens = line.split_whitespace();
            while let Some(token) = tokens.next() {
                if token == "dev" {
                    return tokens.next().map(str::to_owned);
                }
            }
            None
        })
}

/// The interface a route to `address` leaves by — `ip -4 route get <addr>`, then
/// the token after `dev`.
///
/// Distinct from [`read_default_route`]: the roaming scenario needs the
/// interface the *exit* reaches the *client* on, which is not necessarily the
/// one carrying its default route.
pub fn route_dev_to(runner: &dyn NetLeafRunner, address: &str) -> Result<String, String> {
    validate_argv_value("route target address", address)?;
    let output =
        provisioning::capture_allow_failure(runner, &["ip", "-4", "route", "get", address])?;
    let iface = parse_route_dev(&output)
        .ok_or_else(|| format!("no route to {address} names an interface"))?;
    validate_argv_value("route interface", &iface)?;
    Ok(iface)
}

/// The token after the first `dev` in a route-query result.
///
/// The shell's `awk '{for (i=1;i<=NF;i++) if ($i == "dev") {print $(i+1); exit}}'`
/// scanned every field of every line and stopped at the first hit, so unlike
/// [`parse_default_route_iface`] there is no `^default` filter here.
pub fn parse_route_dev(route_output: &str) -> Option<String> {
    let mut tokens = route_output.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "dev" {
            return tokens.next().map(str::to_owned);
        }
    }
    None
}

/// True when any line of a route-query result leaves by an interface that is
/// **not** the tunnel.
///
/// This is deliberately not the negation of [`super::route_via_rustynet`], and
/// the two scenarios use different ones on purpose. `route_via_rustynet` asks
/// "is the tunnel named at all", which a result naming both the tunnel and an
/// underlay device still satisfies; this asks "does anything here leave by an
/// underlay device", which such a result does not. The failback scenario wants
/// the second reading because it is sampling a path mid-transition, where a
/// partially-installed route table can legitimately name both.
pub fn route_leaves_non_tunnel_dev(route_output: &str) -> bool {
    route_output
        .lines()
        .any(|line| parse_route_dev(line).is_some_and(|iface| iface != super::TUNNEL_INTERFACE))
}

/// Add `alias` to `iface` if it is not already there.
///
/// Conditional exactly as the shell's `ip addr show … | grep -Fq … ||
/// ip addr add …` was: re-adding an address that is already present is an error,
/// and a scenario that has already switched once must not fail on its second
/// call.
pub fn add_alias(runner: &dyn NetLeafRunner, iface: &str, alias: &RoamAlias) -> Result<(), String> {
    let cidr = alias.cidr();
    validate_argv_value("roam alias", &cidr)?;
    validate_argv_value("roam interface", iface)?;
    let present = capture_root_allow_failure(runner, &["ip", "addr", "show", "dev", iface])?;
    if !present.contains(&cidr) {
        run_root(runner, &["ip", "addr", "add", &cidr, "dev", iface])?;
    }
    Ok(())
}

// ───────────────────────────── the source pin ─────────────────────────────

/// The private routing table the pin's single route lives in. Not the daemon's
/// table 51820; chosen to be recognisable and unlikely to collide.
pub const SOURCE_PIN_TABLE: u32 = 51873;

/// Priority of the policy rule that sends the exit's underlay `/32` to
/// [`SOURCE_PIN_TABLE`]. The daemon's full-tunnel rule is `10000 lookup 51820`
/// and a LOWER number is evaluated first, so only packets to that one
/// destination are affected and the daemon's rule and table are untouched.
pub const SOURCE_PIN_RULE_PRIORITY: u32 = 9873;

/// What the kernel answers for `ip -4 route get <peer>`: the route the
/// WireGuard flow to the peer actually takes, including the source address it
/// would pick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerPath {
    pub dev: String,
    pub via: Option<Ipv4Addr>,
    pub src: Option<Ipv4Addr>,
}

/// Parse the first line of `ip -4 route get <peer>`.
///
/// Fails closed (`None`) on anything that is not a plain unicast answer for
/// exactly `peer`: `local …`, `broadcast …`, `unreachable …`, an error text, a
/// different destination, a missing `dev`, or a `via`/`src` that is not an IPv4
/// address. A pin built from a misparsed answer would pin the wrong flow.
pub fn parse_route_get(output: &str, peer: Ipv4Addr) -> Option<PeerPath> {
    let line = output.lines().find(|line| !line.trim().is_empty())?;
    let mut tokens = line.split_whitespace();
    if tokens.next()?.parse::<Ipv4Addr>().ok()? != peer {
        return None;
    }
    let mut dev = None;
    let mut via = None;
    let mut src = None;
    while let Some(token) = tokens.next() {
        match token {
            "dev" => dev = Some(tokens.next()?.to_owned()),
            "via" => via = Some(tokens.next()?.parse::<Ipv4Addr>().ok()?),
            "src" => src = Some(tokens.next()?.parse::<Ipv4Addr>().ok()?),
            _ => {}
        }
    }
    Some(PeerPath {
        dev: dev?,
        via,
        src,
    })
}

/// The `ip -4 route get` argv for the WireGuard flow to `peer`: UDP to the
/// WireGuard port. The selectors matter: the pin's policy rule is narrowed to
/// exactly this flow, and only a query carrying the same selectors is answered
/// by it.
pub fn flow_route_get_argv(peer: Ipv4Addr) -> Vec<String> {
    vec![
        "ip".to_owned(),
        "-4".to_owned(),
        "route".to_owned(),
        "get".to_owned(),
        peer.to_string(),
        "ipproto".to_owned(),
        "udp".to_owned(),
        "dport".to_owned(),
        super::WIREGUARD_PORT.to_string(),
    ]
}

/// The raw answer to [`flow_route_get_argv`], trimmed. A non-zero exit reads as
/// empty output (the caller treats an unparsable answer as an error).
pub fn read_flow_route_text(runner: &dyn NetLeafRunner, peer: Ipv4Addr) -> Result<String, String> {
    let argv = flow_route_get_argv(peer);
    provisioning::capture_allow_failure(runner, &as_argv(&argv))
}

/// Ask the kernel which route (and source address) the WireGuard flow to
/// `peer` takes.
pub fn read_peer_path(runner: &dyn NetLeafRunner, peer: Ipv4Addr) -> Result<PeerPath, String> {
    let output = read_flow_route_text(runner, peer)?;
    parse_route_get(&output, peer).ok_or_else(|| {
        format!(
            "cannot resolve a unicast kernel route for the WireGuard flow to {peer}: {output:?}"
        )
    })
}

/// Everything the pin will do, resolved and validated BEFORE any change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourcePin {
    pub alias: RoamAlias,
    pub alias_ip: Ipv4Addr,
    /// The default-route interface, which must also carry the route to the peer.
    pub iface: String,
    /// The exit's underlay address: the only destination the pin affects.
    pub peer: Ipv4Addr,
    /// Next hop of the current route to the peer, if it has one.
    pub via: Option<Ipv4Addr>,
    /// Source the kernel selected for the peer before the pin.
    pub original_src: Option<Ipv4Addr>,
}

impl SourcePin {
    fn peer_prefix(&self) -> String {
        format!("{}/32", self.peer)
    }

    fn route_replace_argv(&self) -> Vec<String> {
        let mut argv = vec![
            "ip".to_owned(),
            "route".to_owned(),
            "replace".to_owned(),
            self.peer_prefix(),
        ];
        if let Some(via) = self.via {
            argv.push("via".to_owned());
            argv.push(via.to_string());
        }
        argv.extend([
            "dev".to_owned(),
            self.iface.clone(),
            "src".to_owned(),
            self.alias_ip.to_string(),
            "table".to_owned(),
            SOURCE_PIN_TABLE.to_string(),
        ]);
        argv
    }

    fn rule_argv(&self, verb: &str) -> Vec<String> {
        vec![
            "ip".to_owned(),
            "rule".to_owned(),
            verb.to_owned(),
            "priority".to_owned(),
            SOURCE_PIN_RULE_PRIORITY.to_string(),
            "to".to_owned(),
            self.peer_prefix(),
            "ipproto".to_owned(),
            "udp".to_owned(),
            "dport".to_owned(),
            super::WIREGUARD_PORT.to_string(),
            "lookup".to_owned(),
            SOURCE_PIN_TABLE.to_string(),
        ]
    }

    /// The exact commands an operator runs on the guest to remove every trace
    /// of the pin by hand. Quoted into every residue message.
    pub fn manual_cleanup(&self) -> String {
        format!(
            "sudo ip rule del priority {SOURCE_PIN_RULE_PRIORITY}; \
             sudo ip route flush table {SOURCE_PIN_TABLE}; \
             sudo ip addr del {} dev {}",
            self.alias.cidr(),
            self.iface
        )
    }
}

fn as_argv(owned: &[String]) -> Vec<&str> {
    owned.iter().map(String::as_str).collect()
}

/// True when `ip addr show` lists `ip` as an address of the interface.
fn addr_listing_has(listing: &str, ip: &str) -> bool {
    let needle = format!("inet {ip}/");
    listing
        .lines()
        .any(|line| line.trim_start().starts_with(&needle))
}

/// True when `ip rule show` has a rule at `priority`.
fn rule_listing_has_priority(listing: &str, priority: u32) -> bool {
    let needle = format!("{priority}:");
    listing.lines().any(|line| {
        line.split_whitespace()
            .next()
            .is_some_and(|first| first == needle)
    })
}

/// Resolve and validate the pin without changing anything.
///
/// Refuses (with the exact manual cleanup) when residue of an earlier crashed
/// run is visible - the alias already on the interface, a rule at the pin's
/// priority, or a non-empty pin table - instead of adopting it: adopting an
/// address this run did not add would let rollback delete it.
///
/// IPv4 only. An IPv6 underlay is refused by name rather than half-supported.
pub fn plan_source_pin(
    runner: &dyn NetLeafRunner,
    exit_address: &str,
    alias: RoamAlias,
) -> Result<SourcePin, String> {
    let peer: Ipv4Addr = exit_address.parse().map_err(|_| {
        format!(
            "the node switch source pin supports IPv4 underlays only; exit address is {exit_address:?}"
        )
    })?;
    let alias_ip: Ipv4Addr = alias.ip.parse().map_err(|_| {
        format!(
            "the node switch source pin supports IPv4 underlays only; roam alias is {:?}",
            alias.ip
        )
    })?;
    validate_argv_value("roam alias", &alias.cidr())?;

    let default_route = read_default_route(runner)?;
    let path = read_peer_path(runner, peer)?;
    validate_argv_value("route interface", &path.dev)?;
    if path.dev != default_route.iface {
        return Err(format!(
            "the route to the exit {peer} leaves by {} but the default route interface is {}; \
             refusing to pin a source on an interface the alias would not be added to",
            path.dev, default_route.iface
        ));
    }

    let pin = SourcePin {
        alias,
        alias_ip,
        iface: default_route.iface,
        peer,
        via: path.via,
        original_src: path.src,
    };

    let addresses =
        capture_root_allow_failure(runner, &["ip", "addr", "show", "dev", pin.iface.as_str()])?;
    if addr_listing_has(&addresses, &pin.alias.ip) {
        return Err(format!(
            "roam alias {} is already on {} before the switch (residue of an earlier run, or an \
             address collision); refusing to adopt it. Clean up with: {}",
            pin.alias.ip,
            pin.iface,
            pin.manual_cleanup()
        ));
    }
    let rules = provisioning::capture_allow_failure(runner, &["ip", "rule", "show"])?;
    if rule_listing_has_priority(&rules, SOURCE_PIN_RULE_PRIORITY) {
        return Err(format!(
            "an ip rule already exists at priority {SOURCE_PIN_RULE_PRIORITY} before the switch \
             (residue of an earlier run); refusing to adopt it. Clean up with: {}",
            pin.manual_cleanup()
        ));
    }
    let table_text = SOURCE_PIN_TABLE.to_string();
    let table = provisioning::capture_allow_failure(
        runner,
        &["ip", "route", "show", "table", table_text.as_str()],
    )?;
    if !table.is_empty() {
        return Err(format!(
            "routing table {SOURCE_PIN_TABLE} is not empty before the switch (residue of an \
             earlier run); refusing to adopt it. Clean up with: {}",
            pin.manual_cleanup()
        ));
    }
    Ok(pin)
}

/// Which of the pin's three changes were actually made. Rollback removes
/// exactly these, so a partially applied pin is undone as precisely as a full one.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AppliedPin {
    pub alias_added: bool,
    pub route_installed: bool,
    pub rule_installed: bool,
}

/// Apply the pin: add the alias, install the single route in the private table,
/// add the policy rule. Returns what was applied even when a step fails, so the
/// caller can roll back precisely.
pub fn apply_source_pin(
    runner: &dyn NetLeafRunner,
    pin: &SourcePin,
) -> (AppliedPin, Result<(), String>) {
    let mut applied = AppliedPin::default();

    let cidr = pin.alias.cidr();
    if let Err(err) = run_root(
        runner,
        &[
            "ip",
            "addr",
            "add",
            cidr.as_str(),
            "dev",
            pin.iface.as_str(),
        ],
    ) {
        return (applied, Err(format!("adding the roam alias failed: {err}")));
    }
    applied.alias_added = true;

    let route = pin.route_replace_argv();
    if let Err(err) = run_root(runner, &as_argv(&route)) {
        return (
            applied,
            Err(format!("installing the pin route failed: {err}")),
        );
    }
    applied.route_installed = true;

    let rule = pin.rule_argv("add");
    if let Err(err) = run_root(runner, &as_argv(&rule)) {
        return (applied, Err(format!("adding the pin rule failed: {err}")));
    }
    applied.rule_installed = true;

    (applied, Ok(()))
}

/// The source address the kernel now selects for the WireGuard flow to the
/// pin's peer. `Ok(None)` means the kernel named no `src`.
pub fn selected_source(
    runner: &dyn NetLeafRunner,
    pin: &SourcePin,
) -> Result<Option<Ipv4Addr>, String> {
    Ok(read_peer_path(runner, pin.peer)?.src)
}

/// Outcome of [`rollback_source_pin`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RollbackReport {
    /// Things still present after the rollback (or that could not be checked).
    /// Empty means the read-back proved the guest is clean.
    pub residue: Vec<String>,
    /// Individual removal commands that failed. Informational: a removal that
    /// failed because the thing was already gone shows up here but not in
    /// `residue`.
    pub errors: Vec<String>,
}

impl RollbackReport {
    pub fn complete(&self) -> bool {
        self.residue.is_empty()
    }

    /// One line for the failure summary and the artifact.
    pub fn describe(&self) -> String {
        if self.complete() {
            "complete".to_owned()
        } else {
            format!("residue: {}", self.residue.join("; "))
        }
    }
}

/// Remove what [`apply_source_pin`] added (rule, route table, alias - in that
/// order) and verify by reading the guest back. Every step is attempted even if
/// an earlier one failed; nothing is swallowed - failures are reported either
/// as `errors` (a removal command failed) or, if the read-back still shows the
/// thing, as `residue`.
pub fn rollback_source_pin(
    runner: &dyn NetLeafRunner,
    pin: &SourcePin,
    applied: AppliedPin,
) -> RollbackReport {
    let mut report = RollbackReport::default();
    let record =
        |report: &mut RollbackReport, what: &str, result: Result<bool, String>| match result {
            Ok(true) => {}
            Ok(false) => report
                .errors
                .push(format!("{what} exited non-zero (it may already be gone)")),
            Err(err) => report.errors.push(format!("{what} failed: {err}")),
        };

    if applied.rule_installed {
        let rule = pin.rule_argv("del");
        let result = run_root_allow_failure(runner, &as_argv(&rule));
        record(&mut report, "ip rule del", result);
    }
    if applied.route_installed {
        let table = SOURCE_PIN_TABLE.to_string();
        let result =
            run_root_allow_failure(runner, &["ip", "route", "flush", "table", table.as_str()]);
        record(&mut report, "ip route flush", result);
    }
    if applied.alias_added {
        let cidr = pin.alias.cidr();
        let result = run_root_allow_failure(
            runner,
            &[
                "ip",
                "addr",
                "del",
                cidr.as_str(),
                "dev",
                pin.iface.as_str(),
            ],
        );
        record(&mut report, "ip addr del", result);
    }

    // Read back. A transport failure here is itself residue: not being able to
    // prove the guest clean is not the same as it being clean.
    let cleanup = pin.manual_cleanup();
    if applied.rule_installed {
        match provisioning::capture_allow_failure(runner, &["ip", "rule", "show"]) {
            Ok(rules) if rule_listing_has_priority(&rules, SOURCE_PIN_RULE_PRIORITY) => {
                report.residue.push(format!(
                    "ip rule at priority {SOURCE_PIN_RULE_PRIORITY} still present (run: {cleanup})"
                ));
            }
            Ok(_) => {}
            Err(err) => report
                .residue
                .push(format!("cannot verify the pin rule is gone: {err}")),
        }
    }
    if applied.route_installed {
        let table = SOURCE_PIN_TABLE.to_string();
        match provisioning::capture_allow_failure(
            runner,
            &["ip", "route", "show", "table", table.as_str()],
        ) {
            Ok(routes) if !routes.is_empty() => report.residue.push(format!(
                "routing table {SOURCE_PIN_TABLE} still has routes (run: {cleanup})"
            )),
            Ok(_) => {}
            Err(err) => report
                .residue
                .push(format!("cannot verify the pin table is empty: {err}")),
        }
    }
    if applied.alias_added {
        match capture_root_allow_failure(runner, &["ip", "addr", "show", "dev", pin.iface.as_str()])
        {
            Ok(listing) if addr_listing_has(&listing, &pin.alias.ip) => {
                report.residue.push(format!(
                    "roam alias {} still on {} (run: {cleanup})",
                    pin.alias.ip, pin.iface
                ));
            }
            Ok(_) => {}
            Err(err) => report
                .residue
                .push(format!("cannot verify the roam alias is gone: {err}")),
        }
    }
    report
}

/// The shell's one-second gap between monitoring samples. Callers pass it
/// through [`LabContext::sleep`](super::provisioning::LabContext::sleep) so a
/// test keeps the sample count while collapsing the wait.
pub const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);

/// Seconds since the unix epoch, as the shell's `date +%s`.
///
/// A clock before the epoch reads as 0 rather than panicking: this value only
/// ever feeds a duration the scenario then measures against its SLO, and a
/// broken clock should fail that comparison, not the process.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::stage::cross_network::substrate::mock::MockLeafRunner;

    const SNAPSHOT: &str =
        "default via 192.168.18.1 dev enp0s1 proto dhcp src 192.168.18.40 metric 100";
    const PEER: &str = "192.168.19.40";
    const ALIAS_IP: &str = "192.168.18.77";

    fn alias() -> RoamAlias {
        RoamAlias {
            ip: ALIAS_IP.to_owned(),
            prefix: 24,
        }
    }

    fn peer() -> Ipv4Addr {
        PEER.parse().expect("peer ip")
    }

    /// The kernel's answer for the WG flow before the pin: the daemon's
    /// table-51820 bypass pin, which has a `via` and no `src`, so the primary
    /// address is selected.
    fn route_get_before() -> String {
        format!("{PEER} via 192.168.18.1 dev enp0s1 table 51820 src 192.168.18.40 uid 0\n    cache")
    }

    /// A guest that answers the planning reads like a clean katana client.
    fn clean_guest() -> MockLeafRunner {
        MockLeafRunner {
            stdout_by_match: vec![
                ("route show default".to_owned(), SNAPSHOT.to_owned()),
                (format!("route get {PEER}"), route_get_before()),
                (
                    "addr show dev".to_owned(),
                    "    inet 192.168.18.40/24 metric 100 brd 192.168.18.255 scope global \
                     dynamic enp0s1"
                        .to_owned(),
                ),
                (
                    "ip rule show".to_owned(),
                    "0:\tfrom all lookup local\n10000:\tfrom all lookup 51820\n32766:\tfrom all lookup main"
                        .to_owned(),
                ),
            ],
            ..MockLeafRunner::default()
        }
    }

    fn pin() -> SourcePin {
        plan_source_pin(&clean_guest(), PEER, alias()).expect("plan on a clean guest")
    }

    #[test]
    fn the_interface_comes_from_the_first_default_route() {
        assert_eq!(
            parse_default_route_iface(SNAPSHOT).as_deref(),
            Some("enp0s1")
        );
        // First wins, exactly as the shell's `awk … exit` did: a second default
        // route must not override the one actually carrying traffic.
        let two = format!("{SNAPSHOT}\ndefault via 10.0.0.1 dev wlan0 metric 600");
        assert_eq!(parse_default_route_iface(&two).as_deref(), Some("enp0s1"));
    }

    #[test]
    fn a_route_table_with_no_default_yields_no_interface() {
        assert_eq!(parse_default_route_iface(""), None);
        assert_eq!(
            parse_default_route_iface("192.168.18.0/24 dev enp0s1 scope link"),
            None,
            "a non-default route must not be mistaken for the default one"
        );
        // A default route with no `dev` names no interface to act on.
        assert_eq!(parse_default_route_iface("default via 192.168.18.1"), None);
    }

    #[test]
    fn reading_the_default_route_fails_closed_when_there_is_none() {
        let runner = MockLeafRunner::default();
        let err = read_default_route(&runner).expect_err("no default route must not read as one");
        assert_eq!(err, "failed to resolve client default underlay interface");
    }

    #[test]
    fn adding_a_plain_alias_is_conditional_on_it_not_being_present() {
        let route_alias = alias();
        let fresh = MockLeafRunner::default();
        add_alias(&fresh, "enp0s1", &route_alias).expect("add on a clean interface");
        let calls = fresh.recorded();
        assert_eq!(calls.len(), 2, "show then add: {calls:?}");
        assert_eq!(
            calls[1],
            vec![
                "sudo",
                "-n",
                "ip",
                "addr",
                "add",
                "192.168.18.77/24",
                "dev",
                "enp0s1"
            ]
        );
        // Re-adding an address that is already present is an error, so a
        // second switch must skip the add rather than fail on it.
        let already = MockLeafRunner {
            stdout_by_match: vec![(
                "addr show dev".to_owned(),
                "    inet 192.168.18.77/24 scope global secondary enp0s1".to_owned(),
            )],
            ..MockLeafRunner::default()
        };
        add_alias(&already, "enp0s1", &route_alias).expect("add when already present");
        assert_eq!(already.recorded().len(), 1, "show only");
    }

    #[test]
    fn route_get_parses_the_daemon_pin_answer_with_via_and_src() {
        let parsed = parse_route_get(&route_get_before(), peer()).expect("parse");
        assert_eq!(parsed.dev, "enp0s1");
        assert_eq!(parsed.via, Some("192.168.18.1".parse().expect("ip")));
        assert_eq!(parsed.src, Some("192.168.18.40".parse().expect("ip")));
    }

    #[test]
    fn route_get_parses_an_on_link_answer_without_via() {
        let parsed = parse_route_get(
            &format!("{PEER} dev enp0s1 src 192.168.18.40 uid 0"),
            peer(),
        )
        .expect("on-link answer");
        assert_eq!(parsed.via, None);
    }

    #[test]
    fn route_get_fails_closed_on_anything_but_a_unicast_answer_for_the_peer() {
        for bad in [
            "",
            "local 192.168.19.40 dev lo src 192.168.19.40 uid 0",
            "broadcast 192.168.19.40 dev enp0s1",
            "RTNETLINK answers: Network is unreachable",
            "192.168.19.41 via 192.168.18.1 dev enp0s1",
            "192.168.19.40 via not-an-ip dev enp0s1",
            "192.168.19.40 via 192.168.18.1",
            "192.168.19.40 via 192.168.18.1 dev enp0s1 src 2001:db8::1",
        ] {
            assert_eq!(parse_route_get(bad, peer()), None, "{bad:?}");
        }
    }

    #[test]
    fn planning_resolves_the_pin_from_two_read_only_queries() {
        let planned = pin();
        assert_eq!(planned.iface, "enp0s1");
        assert_eq!(planned.peer, peer());
        assert_eq!(planned.via, Some("192.168.18.1".parse().expect("ip")));
        assert_eq!(
            planned.original_src,
            Some("192.168.18.40".parse().expect("ip"))
        );
        assert_eq!(planned.alias_ip.to_string(), ALIAS_IP);
    }

    #[test]
    fn planning_makes_no_change_to_the_guest() {
        let runner = clean_guest();
        plan_source_pin(&runner, PEER, alias()).expect("plan");
        for call in runner.recorded() {
            let joined = call.join(" ");
            for forbidden in [" add ", " del ", " replace ", " flush "] {
                assert!(
                    !joined.contains(forbidden),
                    "planning must be read-only, ran: {joined}"
                );
            }
        }
    }

    #[test]
    fn planning_refuses_an_ipv6_underlay_by_name() {
        let err = plan_source_pin(&clean_guest(), "fd00::2", alias()).expect_err("v6 exit");
        assert!(err.contains("IPv4 underlays only"), "{err}");
        let v6_alias = RoamAlias {
            ip: "fd00::99".to_owned(),
            prefix: 64,
        };
        let err = plan_source_pin(&clean_guest(), PEER, v6_alias).expect_err("v6 alias");
        assert!(err.contains("IPv4 underlays only"), "{err}");
    }

    #[test]
    fn planning_refuses_when_the_peer_route_leaves_by_another_interface() {
        let mut guest = clean_guest();
        guest
            .stdout_by_match
            .retain(|(needle, _)| !needle.starts_with("route get"));
        guest.stdout_by_match.push((
            format!("route get {PEER}"),
            format!("{PEER} via 10.0.0.1 dev wlan0 src 10.0.0.9 uid 0"),
        ));
        let err = plan_source_pin(&guest, PEER, alias()).expect_err("interface mismatch");
        assert!(err.contains("wlan0") && err.contains("enp0s1"), "{err}");
    }

    #[test]
    fn planning_refuses_to_adopt_residue_of_a_crashed_run() {
        // The alias already on the interface.
        let mut with_alias = clean_guest();
        with_alias
            .stdout_by_match
            .retain(|(needle, _)| needle != "addr show dev");
        with_alias.stdout_by_match.push((
            "addr show dev".to_owned(),
            format!("    inet 192.168.18.40/24 scope global enp0s1\n    inet {ALIAS_IP}/24 scope global secondary enp0s1"),
        ));
        let err = plan_source_pin(&with_alias, PEER, alias()).expect_err("alias residue");
        assert!(
            err.contains("already on enp0s1") && err.contains("ip addr del"),
            "{err}"
        );

        // A rule at the pin's priority.
        let mut with_rule = clean_guest();
        with_rule
            .stdout_by_match
            .retain(|(needle, _)| needle != "ip rule show");
        with_rule.stdout_by_match.push((
            "ip rule show".to_owned(),
            format!("0:\tfrom all lookup local\n{SOURCE_PIN_RULE_PRIORITY}:\tfrom all to {PEER} lookup {SOURCE_PIN_TABLE}"),
        ));
        let err = plan_source_pin(&with_rule, PEER, alias()).expect_err("rule residue");
        assert!(err.contains("priority 9873"), "{err}");

        // A non-empty pin table.
        let mut with_table = clean_guest();
        with_table.stdout_by_match.push((
            format!("route show table {SOURCE_PIN_TABLE}"),
            format!("{PEER} via 192.168.18.1 dev enp0s1 src {ALIAS_IP}"),
        ));
        let err = plan_source_pin(&with_table, PEER, alias()).expect_err("table residue");
        assert!(err.contains("table 51873"), "{err}");
    }

    #[test]
    fn applying_runs_exactly_the_three_documented_commands_in_order() {
        let planned = pin();
        let runner = MockLeafRunner::default();
        let (applied, result) = apply_source_pin(&runner, &planned);
        result.expect("apply");
        assert_eq!(
            applied,
            AppliedPin {
                alias_added: true,
                route_installed: true,
                rule_installed: true
            }
        );
        let calls = runner.recorded();
        assert_eq!(calls.len(), 3, "{calls:?}");
        assert_eq!(
            calls[0],
            vec![
                "sudo",
                "-n",
                "ip",
                "addr",
                "add",
                "192.168.18.77/24",
                "dev",
                "enp0s1"
            ]
        );
        assert_eq!(
            calls[1],
            vec![
                "sudo",
                "-n",
                "ip",
                "route",
                "replace",
                "192.168.19.40/32",
                "via",
                "192.168.18.1",
                "dev",
                "enp0s1",
                "src",
                "192.168.18.77",
                "table",
                "51873"
            ]
        );
        assert_eq!(
            calls[2],
            vec![
                "sudo",
                "-n",
                "ip",
                "rule",
                "add",
                "priority",
                "9873",
                "to",
                "192.168.19.40/32",
                "ipproto",
                "udp",
                "dport",
                "51820",
                "lookup",
                "51873"
            ]
        );
    }

    #[test]
    fn the_pin_route_omits_via_when_the_peer_is_on_link() {
        let mut guest = clean_guest();
        guest
            .stdout_by_match
            .retain(|(needle, _)| !needle.starts_with("route get"));
        guest.stdout_by_match.push((
            format!("route get {PEER}"),
            format!("{PEER} dev enp0s1 src 192.168.18.40 uid 0"),
        ));
        let on_link = plan_source_pin(&guest, PEER, alias()).expect("plan");
        let route = on_link.route_replace_argv();
        assert!(!route.contains(&"via".to_owned()), "{route:?}");
        assert_eq!(
            &route[3..],
            [
                "192.168.19.40/32",
                "dev",
                "enp0s1",
                "src",
                "192.168.18.77",
                "table",
                "51873"
            ]
        );
    }

    #[test]
    fn a_failing_step_records_exactly_what_had_been_applied() {
        let planned = pin();
        // Call 0 = addr add, 1 = route replace, 2 = rule add.
        for (fail_at, expected) in [
            (0, AppliedPin::default()),
            (
                1,
                AppliedPin {
                    alias_added: true,
                    ..AppliedPin::default()
                },
            ),
            (
                2,
                AppliedPin {
                    alias_added: true,
                    route_installed: true,
                    rule_installed: false,
                },
            ),
        ] {
            let runner = MockLeafRunner {
                fail_on: vec![fail_at],
                failure_stderr: "RTNETLINK answers: File exists".to_owned(),
                ..MockLeafRunner::default()
            };
            let (applied, result) = apply_source_pin(&runner, &planned);
            assert!(result.is_err(), "step {fail_at} must fail the apply");
            assert_eq!(applied, expected, "step {fail_at}");
            assert_eq!(
                runner.recorded().len(),
                fail_at + 1,
                "no step after the failing one may run"
            );
        }
    }

    #[test]
    fn the_selected_source_is_read_from_the_kernel_not_assumed() {
        let planned = pin();
        let pinned = MockLeafRunner {
            stdout_by_match: vec![(
                format!("route get {PEER}"),
                format!("{PEER} via 192.168.18.1 dev enp0s1 table 9873 src {ALIAS_IP} uid 0"),
            )],
            ..MockLeafRunner::default()
        };
        assert_eq!(
            selected_source(&pinned, &planned).expect("read"),
            Some(ALIAS_IP.parse().expect("ip"))
        );
        let unpinned = clean_guest();
        assert_eq!(
            selected_source(&unpinned, &planned).expect("read"),
            Some("192.168.18.40".parse().expect("ip")),
            "an ineffective pin must read back as the OLD source"
        );
    }

    #[test]
    fn rolling_back_removes_exactly_what_was_applied_in_reverse_order_and_verifies() {
        let planned = pin();
        let runner = MockLeafRunner::default();
        let report = rollback_source_pin(
            &runner,
            &planned,
            AppliedPin {
                alias_added: true,
                route_installed: true,
                rule_installed: true,
            },
        );
        assert!(report.complete(), "{report:?}");
        assert!(report.errors.is_empty());
        let calls = runner.recorded();
        assert_eq!(calls.len(), 6, "3 removals + 3 read-backs: {calls:?}");
        assert_eq!(
            calls[0],
            vec![
                "sudo",
                "-n",
                "ip",
                "rule",
                "del",
                "priority",
                "9873",
                "to",
                "192.168.19.40/32",
                "ipproto",
                "udp",
                "dport",
                "51820",
                "lookup",
                "51873"
            ]
        );
        assert_eq!(
            calls[1],
            vec!["sudo", "-n", "ip", "route", "flush", "table", "51873"]
        );
        assert_eq!(
            calls[2],
            vec![
                "sudo",
                "-n",
                "ip",
                "addr",
                "del",
                "192.168.18.77/24",
                "dev",
                "enp0s1"
            ]
        );
        // The read-backs come AFTER every removal, one per thing removed.
        assert_eq!(calls[3], vec!["ip", "rule", "show"]);
        assert_eq!(calls[4], vec!["ip", "route", "show", "table", "51873"]);
        assert_eq!(
            calls[5],
            vec!["sudo", "-n", "ip", "addr", "show", "dev", "enp0s1"]
        );
    }

    #[test]
    fn rolling_back_a_partial_apply_touches_only_what_was_added() {
        let planned = pin();
        let runner = MockLeafRunner::default();
        let report = rollback_source_pin(
            &runner,
            &planned,
            AppliedPin {
                alias_added: true,
                ..AppliedPin::default()
            },
        );
        assert!(report.complete());
        let calls: Vec<String> = runner
            .recorded()
            .iter()
            .map(|call| call.join(" "))
            .collect();
        assert_eq!(calls.len(), 2, "{calls:?}");
        assert!(calls[0].contains("addr del 192.168.18.77/24"), "{calls:?}");
        assert!(
            calls
                .iter()
                .all(|call| !call.contains("rule") && !call.contains("flush")),
            "a rule or table that was never installed must not be touched: {calls:?}"
        );
    }

    #[test]
    fn rolling_back_nothing_runs_nothing() {
        let runner = MockLeafRunner::default();
        let report = rollback_source_pin(&runner, &pin(), AppliedPin::default());
        assert!(report.complete());
        assert!(runner.recorded().is_empty());
    }

    #[test]
    fn rollback_reports_residue_when_the_read_back_still_shows_the_pin() {
        let planned = pin();
        let applied = AppliedPin {
            alias_added: true,
            route_installed: true,
            rule_installed: true,
        };
        // Removal commands "succeed" (default mock) but the guest still shows
        // everything: the report must say so and quote the cleanup.
        let stubborn = MockLeafRunner {
            stdout_by_match: vec![
                (
                    "ip rule show".to_owned(),
                    format!(
                        "{SOURCE_PIN_RULE_PRIORITY}:\tfrom all to {PEER} lookup {SOURCE_PIN_TABLE}"
                    ),
                ),
                (
                    format!("route show table {SOURCE_PIN_TABLE}"),
                    format!("{PEER} dev enp0s1 src {ALIAS_IP}"),
                ),
                (
                    "addr show dev".to_owned(),
                    format!("    inet {ALIAS_IP}/24 scope global secondary enp0s1"),
                ),
            ],
            ..MockLeafRunner::default()
        };
        let report = rollback_source_pin(&stubborn, &planned, applied);
        assert!(!report.complete());
        assert_eq!(report.residue.len(), 3, "{report:?}");
        assert!(report.describe().contains("sudo ip rule del priority 9873"));
    }

    #[test]
    fn rollback_tolerates_failing_removals_but_the_read_back_decides() {
        let planned = pin();
        let applied = AppliedPin {
            alias_added: true,
            route_installed: true,
            rule_installed: true,
        };
        // All three removals exit non-zero (already gone) and the read-back is
        // clean: complete, with the three failures kept as informational errors.
        let gone = MockLeafRunner {
            fail_on: vec![0, 1, 2],
            failure_stderr: "RTNETLINK answers: No such file or directory".to_owned(),
            ..MockLeafRunner::default()
        };
        let report = rollback_source_pin(&gone, &planned, applied);
        assert!(report.complete(), "{report:?}");
        assert_eq!(report.errors.len(), 3);
    }

    #[test]
    fn rollback_treats_an_unreadable_guest_as_residue() {
        let planned = pin();
        let applied = AppliedPin {
            alias_added: true,
            route_installed: true,
            rule_installed: true,
        };
        // Calls 3..=5 are the read-backs; a transport failure on one of them
        // means the guest could not be proven clean.
        let blind = MockLeafRunner {
            transport_error_on: vec![3, 4, 5],
            ..MockLeafRunner::default()
        };
        let report = rollback_source_pin(&blind, &planned, applied);
        assert!(!report.complete());
        assert_eq!(report.residue.len(), 3, "{report:?}");
    }

    #[test]
    fn the_pin_never_replays_guest_supplied_route_text() {
        // The previous teardown fed the guest's own default-route lines to
        // `ip route replace`. Nothing in the pin's argv may come from guest
        // text other than the validated gateway/interface/source values.
        let mut hostile = clean_guest();
        hostile
            .stdout_by_match
            .retain(|(needle, _)| needle != "route show default");
        hostile.stdout_by_match.push((
            "route show default".to_owned(),
            "default dev enp0s1 -o ProxyCommand=touch/x".to_owned(),
        ));
        let planned = plan_source_pin(&hostile, PEER, alias()).expect("plan");
        let route = planned.route_replace_argv().join(" ");
        assert!(!route.contains("ProxyCommand"), "{route}");
        let runner = MockLeafRunner::default();
        let (_, result) = apply_source_pin(&runner, &planned);
        result.expect("apply");
        assert!(
            runner
                .recorded()
                .iter()
                .all(|call| call.iter().all(|token| !token.contains("ProxyCommand")))
        );
    }

    #[test]
    fn the_pin_is_narrowed_to_the_wireguard_flow_and_the_queries_carry_the_same_selectors() {
        let planned = pin();
        // The rule must not capture the other traffic the guest sends to the
        // exit's underlay address (the vxlan substrate's UDP/4789 frames).
        let add = planned.rule_argv("add");
        let del = planned.rule_argv("del");
        for argv in [&add, &del] {
            let text = argv.join(" ");
            assert!(
                text.contains("to 192.168.19.40/32 ipproto udp dport 51820 lookup 51873"),
                "{text}"
            );
        }
        // And the question asked of the kernel - at planning time and for every
        // later verification - is about exactly that flow, because only a
        // query carrying the selectors is answered by the narrowed rule.
        assert_eq!(
            flow_route_get_argv(peer()).join(" "),
            "ip -4 route get 192.168.19.40 ipproto udp dport 51820"
        );
        let runner = clean_guest();
        plan_source_pin(&runner, PEER, alias()).expect("plan");
        selected_source(&runner, &planned).expect("read");
        let route_gets: Vec<String> = runner
            .recorded()
            .iter()
            .map(|call| call.join(" "))
            .filter(|call| call.contains("route get"))
            .collect();
        assert_eq!(route_gets.len(), 2, "{route_gets:?}");
        assert!(
            route_gets
                .iter()
                .all(|call| call.ends_with("ipproto udp dport 51820")),
            "{route_gets:?}"
        );
    }
}
