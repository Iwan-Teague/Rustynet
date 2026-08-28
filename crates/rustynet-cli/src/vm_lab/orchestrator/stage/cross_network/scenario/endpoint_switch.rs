//! Moving a node's underlay endpoint out from under a live tunnel.
//!
//! Two scenarios need this: node-network-switch moves the *client* onto a new
//! underlay address to prove endpoint-change detection and re-convergence, and
//! failback-roaming does the same to prove the roam is recovered from. Both did
//! it the same way in bash — add an IP alias to the default-route interface,
//! repoint the default route's source address at it, and put the original route
//! table back on the way out — so the primitive lives once.
//!
//! # Why the teardown is best-effort but the argv is not
//!
//! The shell's `clear_alias_switch` ended in `|| true` twice over: a lab guest
//! whose route table cannot be restored is already broken, and turning that into
//! the scenario's verdict would report a cleanup failure as an endpoint-switch
//! failure. That tolerance is preserved.
//!
//! What is *not* preserved is how the restore was built. The shell read the
//! guest's own `ip -4 route show default` output back and fed each line to
//! `root ip route replace $line` **unquoted**, so the guest's output was word-split
//! by the orchestrator's shell — a guest that could influence its own route table
//! could inject an argument, or a command. Here each line is split into argv
//! tokens locally and every token is validated before it is used; a line
//! carrying a token that could be read as an option is skipped rather than
//! restored. Skipping is the conservative half of the same tolerance: the
//! alternative is executing it.

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
/// carries it, and the whole `ip -4 route show default` text to put back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultRoute {
    pub iface: String,
    pub snapshot: String,
}

/// Read the node's default route.
///
/// Fails closed when no default route names an interface: every later step
/// (`ip addr add … dev`, `ip route replace default dev`) needs that name, and
/// guessing one would move an address onto the wrong link.
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

/// Add `alias` to the default-route interface and move the default route's
/// source address onto it.
///
/// The add is conditional exactly as the shell's
/// `ip addr show … | grep -Fq … || ip addr add …` was: re-adding an address that
/// is already present is an error, and a scenario that has already switched
/// once must not fail on its second call.
pub fn apply_alias(
    runner: &dyn NetLeafRunner,
    route: &DefaultRoute,
    alias: &RoamAlias,
) -> Result<(), String> {
    let cidr = alias.cidr();
    validate_argv_value("roam alias", &cidr)?;
    let present = capture_root_allow_failure(runner, &["ip", "addr", "show", "dev", &route.iface])?;
    if !present.contains(&cidr) {
        run_root(
            runner,
            &["ip", "addr", "add", &cidr, "dev", route.iface.as_str()],
        )?;
    }
    run_root(
        runner,
        &[
            "ip",
            "route",
            "replace",
            "default",
            "dev",
            route.iface.as_str(),
            "src",
            alias.ip.as_str(),
        ],
    )
}

/// Put the original default route back and remove the alias.
///
/// Best-effort by design — see the module docs. Errors are swallowed rather
/// than returned because this runs on the way out of a scenario whose verdict is
/// already decided, including the failure paths.
pub fn clear_alias(runner: &dyn NetLeafRunner, route: &DefaultRoute, alias: &RoamAlias) {
    for argv in restore_commands(&route.snapshot) {
        let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
        let _ = run_root_allow_failure(runner, &borrowed);
    }
    let cidr = alias.cidr();
    if validate_argv_value("roam alias", &cidr).is_ok() {
        let _ = run_root_allow_failure(
            runner,
            &["ip", "addr", "del", &cidr, "dev", route.iface.as_str()],
        );
    }
}

/// One `ip route replace …` argv per restorable line of a route snapshot.
///
/// A line is skipped when any of its tokens would not be safe as argv — see the
/// module docs on why that is the conservative reading of the shell's `|| true`
/// rather than a new failure mode.
pub fn restore_commands(snapshot: &str) -> Vec<Vec<String>> {
    let mut commands = Vec::new();
    for line in snapshot.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }
        if tokens
            .iter()
            .any(|token| validate_argv_value("route token", token).is_err())
        {
            continue;
        }
        let mut argv = vec!["ip".to_owned(), "route".to_owned(), "replace".to_owned()];
        argv.extend(tokens.into_iter().map(str::to_owned));
        commands.push(argv);
    }
    commands
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
    fn restore_rebuilds_one_ip_route_replace_per_snapshot_line() {
        let commands = restore_commands(SNAPSHOT);
        assert_eq!(commands.len(), 1);
        assert_eq!(
            commands[0],
            vec![
                "ip",
                "route",
                "replace",
                "default",
                "via",
                "192.168.18.1",
                "dev",
                "enp0s1",
                "proto",
                "dhcp",
                "src",
                "192.168.18.40",
                "metric",
                "100",
            ]
        );
    }

    #[test]
    fn restore_skips_a_line_carrying_a_token_that_could_be_read_as_an_option() {
        // The shell fed these lines to `root ip route replace $line` unquoted,
        // so a guest able to influence its own route table could inject an
        // argument. Skipping the line is the conservative reading of the
        // shell's `|| true`; executing it is not.
        let hostile = format!("{SNAPSHOT}\ndefault dev enp0s1 -o ProxyCommand=touch/x");
        let commands = restore_commands(&hostile);
        assert_eq!(
            commands.len(),
            1,
            "only the clean line may be restored: {commands:?}"
        );
        assert!(restore_commands("").is_empty());
    }

    #[test]
    fn applying_the_alias_adds_it_only_when_it_is_not_already_present() {
        let alias = RoamAlias {
            ip: "192.168.18.77".to_owned(),
            prefix: 24,
        };
        let route = DefaultRoute {
            iface: "enp0s1".to_owned(),
            snapshot: SNAPSHOT.to_owned(),
        };

        let fresh = MockLeafRunner::default();
        apply_alias(&fresh, &route, &alias).expect("apply on a clean interface");
        let calls = fresh.recorded();
        assert_eq!(calls.len(), 3, "show, add, replace: {calls:?}");
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
        assert_eq!(
            calls[2],
            vec![
                "sudo",
                "-n",
                "ip",
                "route",
                "replace",
                "default",
                "dev",
                "enp0s1",
                "src",
                "192.168.18.77"
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
        apply_alias(&already, &route, &alias).expect("apply when already present");
        assert_eq!(already.recorded().len(), 2, "show and replace only");
    }

    #[test]
    fn clearing_restores_the_route_table_then_removes_the_alias() {
        let alias = RoamAlias {
            ip: "192.168.18.77".to_owned(),
            prefix: 24,
        };
        let route = DefaultRoute {
            iface: "enp0s1".to_owned(),
            snapshot: SNAPSHOT.to_owned(),
        };
        // Every call fails: teardown is best-effort and must not panic or
        // propagate, because it runs after the verdict is already decided.
        let runner = MockLeafRunner {
            fail_on: vec![0, 1],
            ..MockLeafRunner::default()
        };
        clear_alias(&runner, &route, &alias);
        let calls = runner.recorded();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0][..5], ["sudo", "-n", "ip", "route", "replace"]);
        assert_eq!(
            calls[1],
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
    }
}
