//! Underlay attestation (AQ-254 parts b+c, 2026-10-03; reworked 2026-10-03
//! per the independent b75 review).
//!
//! Background (b72/Azure report): a `dataplane_endpoint` inventory override
//! is meant to publish an owner cloud node's PUBLIC WireGuard address. If
//! that address is itself inside a private range (CGNAT/tailnet 100.64.0.0/10,
//! RFC1918, loopback, link-local, …), peers are handed an unroutable
//! "public" endpoint and the mesh silently degrades to non-traversal — a
//! fail-open deployment. This module is the enforcement + verification half:
//!
//! * (b) [`crate::vm_lab::orchestrator::stage::collect_pubkeys`] refuses to
//!   record a `dataplane_endpoint` override whose address is not public
//!   ([`is_non_public_dataplane_ip`]).
//! * (c) the two live dataplane stages — `mesh_status_validation` and
//!   `traffic_test_matrix` — capture the LIVE WireGuard peer endpoints from
//!   every node whose inventory entry declares a `dataplane_endpoint` and
//!   FAIL the stage when any observed endpoint sits on a non-public
//!   underlay ([`attest_inventory_dataplane_nodes`]).
//!
//! Deliberate scoping (b72 evidence): the rustynet mesh IPs themselves
//! (100.64.0.x/100.78.x/100.79.x) sit INSIDE 100.64.0.0/10, so attestation
//! keys on the WireGuard ENDPOINT address only — never on mesh/allowed-ips
//! values. The substrate-overlay override path in collect_pubkeys is NOT
//! range-checked: a provisioned overlay address is by definition not the
//! public internet and is already gated by the substrate seam.
//!
//! Capture contract (mirrors `node_diagnostics`):
//! * argv-only through the [`RemoteShellHost`] seam, bounded by a remote
//!   `timeout`, no shell construction, no sudo.
//! * `wg show all endpoints` — NEVER the `dump` form (private keys). The
//!   live guest interface is named per-node, so the `all` spelling is what
//!   reaches the endpoints table on every backend.
//! * A non-zero exit is tolerated and falls through to the daemon-status
//!   fallback (a userspace-boringtun guest owns a TUN device `wg` cannot
//!   see — exactly why the fallback exists); a TRANSPORT failure fails
//!   closed.
//! * An empty endpoint set fails closed: these stages run post-handshake,
//!   so a node with peers must have endpoints to show.
//!
//! Documented limits (b83 rework; each was a review finding, recorded here
//! as an explicit owner-scoped limit rather than silently inherited):
//! * Declared WINDOWS nodes fail closed / are unsupported (review F2): the
//!   capture runs POSIX `timeout 10 wg show all endpoints`; with `wg`
//!   absent the tolerated non-zero exit falls through to the daemon-status
//!   fallback, whose default on Windows is `Err(UnsupportedPlatform)` — so
//!   a node declaring `dataplane_endpoint` on Windows fails the stage
//!   instead of attesting nothing. No tracked inventory declares the field
//!   on a Windows node; supporting one means a Windows argv spelling, an
//!   owner decision not taken here.
//! * IPv6 unique-local (fc00::/7) is ALLOWED (review F6), per AQ-254's
//!   letter, which names CGNAT/loopback (b) and 100.64.0.0/10 + RFC1918
//!   (c) and no more. Flagging ULA would be a policy tightening only the
//!   owner can make (open question in the b75 review).
//! * A peer that legitimately presents a CGNAT/RFC1918 endpoint — a peer
//!   behind carrier-grade NAT whose public path shows 100.64/10 at the
//!   exit, or a same-L2 peer — FAILS the stage (review F7), per AQ-254's
//!   letter ("fail or downgrade ... when a scenario that claims a public
//!   dataplane shows an endpoint inside 100.64.0.0/10 or RFC 1918"). This
//!   implementation fails; a downgrade policy would be an owner change.
//! * A v4-mapped IPv6 endpoint (`::ffff:a.b.c.d`, review F1) is judged by
//!   its embedded IPv4 address, never as a bare v6 address.
//! * A declared alias with NO role assignment in this run is REPORTED, not
//!   failed (b85 revision of review F3): it produces a
//!   `verdict=not_in_run` evidence line and never a violation. An alias
//!   outside the run has nothing to attest, and the lab launcher
//!   (katanalab-azure.sh) always loads the Azure overlay — which declares
//!   `azure-vm-1` with a `dataplane_endpoint` — so a katana-only run would
//!   otherwise fail `mesh_status_validation` and `traffic_test_matrix` on a
//!   node that is not in the run. Every ASSIGNED node keeps the fail-closed
//!   contract unchanged (no adapter, capture errors, unparseable or
//!   non-public endpoints, unloadable inventory).

use crate::vm_lab::orchestrator::adapter::node_adapter::NodeAdapter;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::remote_shell::RemoteShellHost;
use crate::vm_lab::orchestrator::stage::collect_pubkeys::load_dataplane_overrides;

/// `wg show all endpoints`, bounded on the node like every diagnostics
/// command. `all` (not a fixed interface name) because the live guest
/// interface is named per-node.
const WG_ENDPOINTS_ARGV: &[&str] = &["timeout", "10", "wg", "show", "all", "endpoints"];

/// True when `ip` is NOT a legitimate public underlay address for a
/// `dataplane_endpoint` override. The complement of `node_diagnostics`'s
/// `is_global_ip`, minus the ULA carve-out decision below:
///
/// * v4: RFC1918 private, loopback, link-local (169.254/16), unspecified,
///   multicast, broadcast, reserved (240/4), and CGNAT/tailnet
///   100.64.0.0/10 — the RFC 6598 range tailscale-style overlays live in,
///   which is precisely the false-public case b72 exposed.
/// * v6: loopback (::1), unspecified (::), multicast (ff00::/8) and
///   link-local (fe80::/10).
/// * v4-mapped v6 (`::ffff:a.b.c.d`, b83 rework / review F1): judged by the
///   EMBEDDED IPv4 address, so the mapped form of a non-public v4 address
///   cannot launder itself through the v6 arm (attestation must not hinge
///   on which family a producer chose to format).
///
/// IPv6 unique-local (fc00::/7) is deliberately NOT flagged: a
/// point-to-point ULA dataplane between owner-owned nodes is routable and
/// explicitly permitted by the AQ-254 wording ("CGNAT/loopback"), and
/// flagging it would reject configurations the action item allows.
pub(crate) fn is_non_public_dataplane_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => is_non_public_v4(v4),
        std::net::IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_non_public_v4(v4);
            }
            let seg0 = v6.segments()[0];
            let link_local = (seg0 & 0xffc0) == 0xfe80;
            v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() || link_local
        }
    }
}

/// The v4 half of [`is_non_public_dataplane_ip`], shared by the v4 arm and
/// the v4-mapped branch of the v6 arm.
fn is_non_public_v4(v4: std::net::Ipv4Addr) -> bool {
    let o = v4.octets();
    let cgnat = o[0] == 100 && (o[1] & 0xc0) == 64;
    v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_multicast()
        || v4.is_broadcast()
        || o[0] >= 240
        || cgnat
}

/// Parse `wg show [all] endpoints` output into `(peer, endpoint)` pairs,
/// tolerantly:
///
/// * `wg show <iface> endpoints` prints `<pubkey>\t<endpoint>` (2 fields);
/// * `wg show all endpoints` prints `<iface>\t<pubkey>\t<endpoint>` (3);
/// * a peer with no endpoint yet prints `(none)` — that is "no datum", not
///   an endpoint, and contributes nothing;
/// * both the tab-separated spelling the tool prints and plain
///   whitespace separation are accepted.
///
/// The ENDPOINT column (last field) is the only value attestation judges;
/// the peer label (second-to-last) is carried for violation messages only.
pub(crate) fn parse_wg_show_all_endpoint_pairs(output: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for line in output.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 2 {
            continue;
        }
        let endpoint = fields[fields.len() - 1];
        if endpoint == "(none)" {
            continue;
        }
        let peer = fields[fields.len() - 2];
        pairs.push((peer.to_owned(), endpoint.to_owned()));
    }
    pairs
}

/// Parse the daemon `status` line's `managed_peer_endpoints=` field into
/// `(node_id, endpoint)` pairs — the same grammar
/// [`crate::vm_lab::orchestrator::stage::cross_network::scenario::parse_daemon_managed_peer_endpoints`]
/// accepts (`node_id/addr:port` joined by `+`, `node_id/none` = no datum),
/// but keeping the peer's node_id so a violation can name it.
pub(crate) fn parse_daemon_managed_peer_endpoint_pairs(status_line: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for field in status_line.split_whitespace() {
        let Some(value) = field.strip_prefix("managed_peer_endpoints=") else {
            continue;
        };
        for entry in value.split('+') {
            let Some((node_id, endpoint)) = entry.split_once('/') else {
                continue;
            };
            if node_id.is_empty() || endpoint.is_empty() || endpoint == "none" {
                continue;
            }
            pairs.push((node_id.to_owned(), endpoint.to_owned()));
        }
    }
    pairs
}

/// Extract the host half of a `host:port` endpoint as an IP address.
/// IPv4 as-is; IPv6 bracketed (`[2001:db8::7]:51820` — the shape every
/// producer here uses, since both `wg` and the daemon render SocketAddrs).
/// Anything else — a hostname, a missing port, an unclosed bracket — is an
/// error: an endpoint that cannot be pinned to an address must fail the
/// attestation closed, never be waved through as "unknown, presumed fine".
pub(crate) fn endpoint_host(endpoint: &str) -> Result<std::net::IpAddr, String> {
    let host = if let Some(rest) = endpoint.strip_prefix('[') {
        let (inside, after) = rest.split_once(']').ok_or_else(|| {
            format!("endpoint {endpoint:?} opens an IPv6 bracket but never closes it")
        })?;
        match after.strip_prefix(':') {
            Some(port) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => inside,
            _ => {
                return Err(format!(
                    "endpoint {endpoint:?} carries no :port after the IPv6 bracket"
                ));
            }
        }
    } else {
        match endpoint.rsplit_once(':') {
            Some((host, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
                host
            }
            _ => return Err(format!("endpoint {endpoint:?} is not host:port")),
        }
    };
    host.parse::<std::net::IpAddr>()
        .map_err(|_| format!("endpoint {endpoint:?} host {host:?} is not an IP address"))
}

/// Attest one node's observed `(peer, endpoint)` pairs. Empty input is the
/// caller's fail-closed decision (capture reports it); every pair here must
/// either parse to a PUBLIC endpoint address or produce a violation naming
/// the node, the peer, the endpoint, and why it failed.
pub(crate) fn attest_node_endpoint_pairs(alias: &str, pairs: &[(String, String)]) -> Vec<String> {
    let mut violations = Vec::new();
    for (peer, endpoint) in pairs {
        match endpoint_host(endpoint) {
            Ok(ip) if is_non_public_dataplane_ip(ip) => violations.push(format!(
                "{alias}: underlay attestation FAILED: peer {peer} announces endpoint \
                 {endpoint} — underlay was not the public internet ({ip} is a non-public \
                 address)"
            )),
            Ok(_) => {}
            Err(e) => violations.push(format!(
                "{alias}: underlay attestation FAILED: peer {peer} endpoint {endpoint} is \
                 unparseable ({e}) — failing closed"
            )),
        }
    }
    violations
}

/// Capture one node's live WireGuard peer endpoints: `wg show all endpoints`
/// first, the daemon status line's `managed_peer_endpoints=` as the fallback
/// (userspace-boringtun guests show `wg` an empty table). A non-zero remote
/// exit is tolerated (tool missing / device unseen are the fallback's own
/// cases); a TRANSPORT failure is not — capture fails closed there. An empty
/// result from BOTH sources is an error, never an empty success: these
/// stages run post-handshake, so a node with peers must have endpoints.
pub(crate) fn capture_node_endpoint_pairs(
    adapter: &dyn NodeAdapter,
) -> Result<Vec<(String, String)>, String> {
    let shell = adapter
        .shell_host()
        .map_err(|e| format!("remote shell unavailable: {e}"))?;
    let pairs = run_wg_endpoints(shell.as_ref())?;
    if !pairs.is_empty() {
        return Ok(pairs);
    }
    let status_line = adapter
        .collect_daemon_status()
        .map_err(|e| format!("daemon-status fallback unavailable: {e}"))?;
    let pairs = parse_daemon_managed_peer_endpoint_pairs(&status_line);
    if pairs.is_empty() {
        return Err(
            "`wg show all endpoints` yielded no peer endpoints AND the daemon status \
                    carries no managed_peer_endpoints entries — no peer has an endpoint yet, \
                    failing closed"
                .to_owned(),
        );
    }
    Ok(pairs)
}

fn run_wg_endpoints(shell: &dyn RemoteShellHost) -> Result<Vec<(String, String)>, String> {
    let status = shell
        .run_argv(WG_ENDPOINTS_ARGV, &[], &[])
        .map_err(|e| format!("`wg show all endpoints` transport failure: {e}"))?;
    Ok(parse_wg_show_all_endpoint_pairs(&String::from_utf8_lossy(
        &status.stdout,
    )))
}

/// Per-stage attestation result: every DECLARED node (inventory
/// `dataplane_endpoint`) was either attested clean (an evidence line),
/// reported as not part of this run (`verdict=not_in_run`, also an evidence
/// line), or produced one or more violations. `Err` is reserved for the
/// inventory itself being unloadable — the same fail-closed contract
/// collect_pubkeys uses for its overrides.
pub(crate) struct UnderlayAttestationReport {
    pub(crate) violations: Vec<String>,
    pub(crate) evidence_lines: Vec<String>,
}

/// Attest every node whose inventory entry declares a `dataplane_endpoint`.
/// Nodes without a declaration are out of scope (behaviour unchanged); a
/// topology with no inventory context has an empty override set and attests
/// nothing. A declared node that cannot be captured, or whose captured
/// endpoints include a non-public (or unparseable) address, becomes a
/// violation the caller turns into a stage failure — never a warning. A
/// DECLARED alias with NO role assignment in this run is REPORTED, not
/// failed (b85 revision of b83's review F3): an alias outside the run has
/// nothing to attest, so it leaves a `verdict=not_in_run` evidence line and
/// never a violation.
pub(crate) fn attest_inventory_dataplane_nodes(
    ctx: &OrchestrationContext,
    stage: &str,
) -> Result<UnderlayAttestationReport, String> {
    let overrides = load_dataplane_overrides(ctx.inventory_path.as_deref())?;
    let mut report = UnderlayAttestationReport {
        violations: Vec::new(),
        evidence_lines: Vec::new(),
    };
    if overrides.is_empty() {
        return Ok(report);
    }
    for assignment in &ctx.assignments {
        let alias = assignment.alias.as_str();
        if !overrides.contains_key(alias) {
            continue;
        }
        let Some(adapter) = ctx.adapters.get(alias) else {
            report.violations.push(format!(
                "{alias}: underlay attestation FAILED: no adapter for node — failing closed"
            ));
            continue;
        };
        match capture_node_endpoint_pairs(adapter.as_ref()) {
            Ok(pairs) => {
                let violations = attest_node_endpoint_pairs(alias, &pairs);
                if violations.is_empty() {
                    report.evidence_lines.push(format!(
                        "underlay_attestation: node={alias} stage={stage} peers={} \
                         verdict=all_public",
                        pairs.len()
                    ));
                } else {
                    report.violations.extend(violations);
                }
            }
            Err(e) => report
                .violations
                .push(format!("{alias}: underlay attestation FAILED: {e}")),
        }
    }
    // b85 revision of b83's review F3: a declared alias with no role
    // assignment in this run has nothing to attest (no adapter, no captured
    // endpoints), so it is REPORTED as an evidence line, never a violation.
    // The lab launcher (katanalab-azure.sh) always loads the Azure overlay,
    // which declares `azure-vm-1` with a `dataplane_endpoint`; failing the
    // stage here would make any katana-only run started through it fail on
    // an alias that is not in the run at all. Sorted, so the report order
    // is deterministic.
    let mut unassigned: Vec<&String> = overrides
        .keys()
        .filter(|alias| !ctx.assignments.iter().any(|a| &a.alias == *alias))
        .collect();
    unassigned.sort();
    for alias in unassigned {
        report.evidence_lines.push(format!(
            "underlay_attestation: node={alias} stage={stage} verdict=not_in_run"
        ));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> std::net::IpAddr {
        s.parse().expect("test ip")
    }

    #[test]
    fn public_addresses_pass_and_non_public_are_flagged() {
        for ok in [
            "203.0.113.7",  // TEST-NET-3: public-class documentation range
            "198.51.100.5", // TEST-NET-2
            "192.0.2.10",   // TEST-NET-1
            "8.8.8.8",
            "2001:db8::7",
            "2620:fe::fe",
        ] {
            assert!(
                !is_non_public_dataplane_ip(ip(ok)),
                "{ok} must count as a public underlay address"
            );
        }
        for bad in [
            "100.64.0.1",    // CGNAT low edge
            "100.100.5.5",   // tailnet (b72's live endpoint class)
            "100.127.255.9", // CGNAT high edge
            "10.0.0.5",
            "172.16.5.5",
            "192.168.1.5",
            "127.0.0.1",
            "169.254.1.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "240.0.0.1",
            "::1",
            "::",
            "fe80::1",
            "ff02::1",
        ] {
            assert!(
                is_non_public_dataplane_ip(ip(bad)),
                "{bad} must be flagged as a non-public underlay address"
            );
        }
    }

    #[test]
    fn wg_show_all_pairs_parse_tolerantly() {
        let pubkey_a = "a".repeat(44);
        let pubkey_b = "b".repeat(44);
        // `wg show all endpoints` spelling (3 fields), tab-separated.
        let three_field = format!("wg0\t{pubkey_a}\t203.0.113.7:51820");
        // `wg show <iface> endpoints` spelling (2 fields), spaces.
        let two_field = format!("{pubkey_b} 198.51.100.9:443");
        // A peer with no endpoint yet: no datum.
        let none = format!("wg0\t{pubkey_a}\t(none)");
        let mixed = format!("{three_field}\n{none}\n{two_field}\n\n  \n");
        let pairs = parse_wg_show_all_endpoint_pairs(&mixed);
        assert_eq!(
            pairs,
            vec![
                (pubkey_a.clone(), "203.0.113.7:51820".to_owned()),
                (pubkey_b, "198.51.100.9:443".to_owned()),
            ]
        );
        assert!(parse_wg_show_all_endpoint_pairs("").is_empty());
        assert!(parse_wg_show_all_endpoint_pairs("(none)").is_empty());
        assert!(parse_wg_show_all_endpoint_pairs("onlyonefield").is_empty());
    }

    /// The attestation judges the ENDPOINT column only: a mesh/allowed-ips
    /// value must never be mistaken for the underlay (b72 — the mesh IPs sit
    /// inside 100.64.0.0/10). A public endpoint attests clean even when the
    /// peer label carries mesh-ish text, and the peer label alone never
    /// creates a pair.
    #[test]
    fn only_the_endpoint_column_is_judged() {
        let mesh_label_peer = "peer-allowed-ips-100.64.0.2-32".to_owned();
        let pairs = vec![(mesh_label_peer, "203.0.113.7:51820".to_owned())];
        assert!(attest_node_endpoint_pairs("node-a", &pairs).is_empty());

        let tailnet = vec![("peer-x".to_owned(), "100.100.5.5:51820".to_owned())];
        let violations = attest_node_endpoint_pairs("node-a", &tailnet);
        assert_eq!(violations.len(), 1);
        let v = &violations[0];
        for needle in [
            "node-a",
            "peer-x",
            "100.100.5.5:51820",
            "not the public internet",
        ] {
            assert!(v.contains(needle), "violation must name {needle}: {v}");
        }
    }

    #[test]
    fn endpoint_host_parses_v4_v6_and_rejects_garbage() {
        assert_eq!(
            endpoint_host("203.0.113.7:51820").expect("v4"),
            ip("203.0.113.7")
        );
        assert_eq!(
            endpoint_host("[2001:db8::7]:51820").expect("bracketed v6"),
            ip("2001:db8::7")
        );
        for garbage in [
            "no-port-here",
            "host:",
            "[2001:db8::7",
            "[2001:db8::7]51820",
            "[2001:db8::7]:",
            "example.com:51820",
            "203.0.113.7",
        ] {
            assert!(
                endpoint_host(garbage).is_err(),
                "{garbage} must not parse as an address-bearing endpoint"
            );
        }
    }

    /// An unparseable endpoint fails closed with a violation — "unknown" is
    /// never treated as "presumed public".
    #[test]
    fn unparseable_endpoint_is_a_violation_not_a_pass() {
        let pairs = vec![("peer-y".to_owned(), "not-an-endpoint".to_owned())];
        let violations = attest_node_endpoint_pairs("node-a", &pairs);
        assert_eq!(violations.len(), 1);
        assert!(
            violations[0].contains("failing closed"),
            "{}",
            violations[0]
        );
    }

    /// b83 rework (review F1): an IPv4-mapped IPv6 address
    /// (`::ffff:a.b.c.d` — what any producer that Displays a v6-mapped
    /// SocketAddr renders) is classified by its EMBEDDED IPv4 address. On
    /// the pre-rework classifier every mapped bad address below attested
    /// PUBLIC (the v6 arm saw seg0 = 0 and matched nothing) — these
    /// assertions are the before/after witness.
    #[test]
    fn v4_mapped_ipv6_is_classified_by_its_embedded_ipv4() {
        for bad in [
            "::ffff:100.100.5.5",   // mapped CGNAT/tailnet (b72's live class)
            "::ffff:100.64.0.1",    // mapped CGNAT low edge
            "::ffff:100.127.255.9", // mapped CGNAT high edge
            "::ffff:10.0.0.5",      // mapped RFC1918
            "::ffff:172.16.5.5",    // mapped RFC1918
            "::ffff:192.168.1.5",   // mapped RFC1918
            "::ffff:127.0.0.1",     // mapped loopback
            "::ffff:169.254.1.1",   // mapped link-local
            "::ffff:0.0.0.0",       // mapped unspecified
        ] {
            assert!(
                is_non_public_dataplane_ip(ip(bad)),
                "{bad} must be flagged via its embedded IPv4 address"
            );
        }
        // The mapped form of a public address stays public: the same verdict
        // as its v4 spelling, whichever family the producer emitted.
        for good in [
            "::ffff:203.0.113.7",
            "::ffff:198.51.100.5",
            "::ffff:8.8.8.8",
        ] {
            assert!(
                !is_non_public_dataplane_ip(ip(good)),
                "{good} must stay a public underlay address"
            );
        }
    }

    /// b83 rework (review F1), the full endpoint path: the review's exact
    /// example `[::ffff:100.100.5.5]:51820` is a violation naming the
    /// embedded v4 address; the mapped public form attests clean.
    #[test]
    fn bracketed_v4_mapped_endpoint_is_judged_by_its_embedded_ipv4() {
        let bad = vec![("peer-m".to_owned(), "[::ffff:100.100.5.5]:51820".to_owned())];
        let violations = attest_node_endpoint_pairs("node-a", &bad);
        assert_eq!(violations.len(), 1, "{violations:?}");
        let v = &violations[0];
        for needle in [
            "node-a",
            "peer-m",
            "[::ffff:100.100.5.5]:51820",
            "not the public internet",
        ] {
            assert!(v.contains(needle), "violation must name {needle}: {v}");
        }

        let good = vec![("peer-g".to_owned(), "[::ffff:203.0.113.7]:51820".to_owned())];
        assert!(
            attest_node_endpoint_pairs("node-a", &good).is_empty(),
            "the mapped form of a public address attests clean"
        );
    }

    /// b85 revision of b83's review F3: an inventory alias that declares a
    /// `dataplane_endpoint` but has NO role assignment in the run is
    /// REPORTED as an evidence line (`verdict=not_in_run`) and never
    /// violates the stage — an alias outside the run has nothing to attest.
    /// (The b83 spelling failed the stage here, which made any katana-only
    /// run launched through katanalab-azure.sh fail on the Azure overlay's
    /// out-of-run alias.)
    #[test]
    fn declared_but_unassigned_alias_is_reported_not_failed() {
        let dir = std::env::temp_dir().join(format!(
            "underlay-attest-unassigned-{}",
            crate::vm_lab::unique_suffix()
        ));
        std::fs::create_dir_all(&dir).expect("inventory dir");
        let inventory = dir.join("vm_lab_inventory.json");
        std::fs::write(
            inventory.as_path(),
            r#"{
              "version": 1,
              "entries": [
                {
                  "alias": "ghost-node",
                  "ssh_target": "100.64.15.9",
                  "dataplane_endpoint": "203.0.113.7",
                  "platform": "linux"
                }
              ]
            }"#,
        )
        .expect("write inventory");

        let mut ctx = OrchestrationContext::new(Vec::new(), dir.join("reports"), "net".to_owned());
        ctx.inventory_path = Some(inventory);
        let report = attest_inventory_dataplane_nodes(&ctx, "test_stage")
            .expect("the inventory itself is loadable");
        assert!(
            report.violations.is_empty(),
            "an alias outside the run must never violate: {:?}",
            report.violations
        );
        assert_eq!(
            report.evidence_lines.len(),
            1,
            "{:?}",
            report.evidence_lines
        );
        let e = &report.evidence_lines[0];
        for needle in ["ghost-node", "stage=test_stage", "verdict=not_in_run"] {
            assert!(e.contains(needle), "evidence must name {needle}: {e}");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression guard on the b85 F3 revision: the not_in_run evidence
    /// path never swallows a real failure. A node that IS assigned keeps
    /// the fail-closed contract — a captured non-public endpoint still
    /// violates — while a second declared alias outside the run sits in the
    /// same report as a mere `verdict=not_in_run` evidence line.
    #[test]
    fn assigned_node_still_fails_on_non_public_endpoint_despite_not_in_run_alias() {
        use crate::vm_lab::orchestrator::role::NodeRole;
        use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
        use crate::vm_lab::orchestrator::stage::node_diagnostics::test_support;

        let dir = std::env::temp_dir().join(format!(
            "underlay-attest-mixed-{}",
            crate::vm_lab::unique_suffix()
        ));
        std::fs::create_dir_all(&dir).expect("inventory dir");
        let inventory = dir.join("vm_lab_inventory.json");
        std::fs::write(
            inventory.as_path(),
            r#"{
              "version": 1,
              "entries": [
                {
                  "alias": "real-node",
                  "ssh_target": "100.64.15.8",
                  "dataplane_endpoint": "203.0.113.7",
                  "platform": "linux"
                },
                {
                  "alias": "ghost-node",
                  "ssh_target": "100.64.15.9",
                  "dataplane_endpoint": "203.0.113.8",
                  "platform": "linux"
                }
              ]
            }"#,
        )
        .expect("write inventory");

        let log: test_support::EventLog = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let responder: std::sync::Arc<test_support::Responder> = std::sync::Arc::new(|argv| {
            if argv.last().map(String::as_str) == Some("endpoints") {
                let pubkey = "c".repeat(44);
                test_support::ok(&format!("wg0\t{pubkey}\t100.100.5.5:51820"))
            } else {
                test_support::rc(1, "unexpected argv in test")
            }
        });
        let mut ctx = OrchestrationContext::new(
            vec![NodeRoleAssignment {
                alias: "real-node".to_owned(),
                role: NodeRole::Exit,
            }],
            dir.join("reports"),
            "net".to_owned(),
        );
        ctx.inventory_path = Some(inventory);
        ctx.adapters.insert(
            "real-node".to_owned(),
            Box::new(test_support::ShellAdapter::new(
                "real-node",
                &log,
                responder,
            )),
        );

        let report = attest_inventory_dataplane_nodes(&ctx, "test_stage")
            .expect("the inventory itself is loadable");

        // The assigned node's non-public captured endpoint still fails.
        assert_eq!(report.violations.len(), 1, "{:?}", report.violations);
        let v = &report.violations[0];
        for needle in ["real-node", "100.100.5.5:51820", "not the public internet"] {
            assert!(v.contains(needle), "violation must name {needle}: {v}");
        }

        // The out-of-run declared alias is reported, never failed, and the
        // assigned node leaves no all_public line (it violated).
        assert_eq!(
            report.evidence_lines.len(),
            1,
            "{:?}",
            report.evidence_lines
        );
        let e = &report.evidence_lines[0];
        assert!(
            e.contains("ghost-node") && e.contains("verdict=not_in_run"),
            "the only evidence line must be ghost-node's not_in_run: {e}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
