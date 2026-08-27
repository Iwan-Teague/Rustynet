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
}

/// Reject argv elements that could break the quoting boundary. Every element
/// is later single-quoted, so the only characters that must never appear are
/// control characters (which would corrupt logs and can smuggle terminal
/// escapes) and empty elements (which vanish visually).
fn validate_argv(argv: &[&str]) -> Result<(), String> {
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

/// One vxlan link this run created on a guest (exact teardown targets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedLink {
    pub alias: String,
    pub link: String,
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
    /// Links actually created so far — appended as each `ip link add`
    /// succeeds, so a partial setup still knows exactly what to remove.
    pub created_links: Vec<CreatedLink>,
}

/// Setup failure that keeps the partial state: the stage stores
/// `partial` on the context so the always-run teardown stage can remove
/// whatever was created before the failure (fail closed, never fail-and-leak).
#[derive(Debug)]
pub struct SubstrateSetupFailure {
    pub message: String,
    pub partial: SubstrateHandle,
}

/// WHERE the overlay topology lives. Provisioned once by the
/// `cross_network_substrate_setup` stage (before `collect_pubkeys`), torn down
/// by the always-run `cross_network_substrate_teardown` stage.
pub trait CrossNetworkSubstrateProvider {
    fn id(&self) -> &'static str;

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
            created_links: Vec::new(),
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
            created_links: Vec::new(),
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
            handle.created_links.push(CreatedLink {
                alias: alias.clone(),
                link: VXLAN_LINK_NAME.to_owned(),
            });
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
        let targets: Vec<CreatedLink> = if handle.created_links.is_empty() {
            handle
                .record
                .participants
                .iter()
                .map(|alias| CreatedLink {
                    alias: alias.clone(),
                    link: VXLAN_LINK_NAME.to_owned(),
                })
                .collect()
        } else {
            handle.created_links.clone()
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
            match runner.run(&["sudo", "-n", "ip", "link", "del", &target.link]) {
                Err(err) => errors.push(format!("{}: {err}", target.alias)),
                Ok(output) if !output.success => {
                    // Already-gone is the idempotent success case; anything
                    // else is potential residue and must fail the stage.
                    if !output.stderr.contains("Cannot find device") {
                        errors.push(format!(
                            "{}: delete {} failed: {}",
                            target.alias,
                            target.link,
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

#[cfg(test)]
pub(crate) mod mock {
    use super::{LeafOutput, NetLeafRunner};
    use std::sync::Mutex;

    /// Scriptable in-memory runner: records every argv, and fails (exit
    /// status or transport) at the scripted call indexes.
    #[derive(Default)]
    pub struct MockLeafRunner {
        pub calls: Mutex<Vec<Vec<String>>>,
        /// 0-based call indexes that return `success: false`.
        pub fail_on: Vec<usize>,
        /// 0-based call indexes that return `Err` (transport failure).
        pub transport_error_on: Vec<usize>,
        /// stderr text attached to failing calls.
        pub failure_stderr: String,
    }

    impl NetLeafRunner for MockLeafRunner {
        fn run(&self, argv: &[&str]) -> Result<LeafOutput, String> {
            let mut calls = self.calls.lock().expect("mock runner lock");
            let index = calls.len();
            calls.push(argv.iter().map(|s| (*s).to_owned()).collect());
            if self.transport_error_on.contains(&index) {
                return Err(format!("mock transport failure at call {index}"));
            }
            Ok(LeafOutput {
                success: !self.fail_on.contains(&index),
                stdout: String::new(),
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
        assert_eq!(handle.created_links.len(), 3);
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
    fn vxlan_setup_failure_keeps_partial_created_links_for_teardown() {
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
            failure.partial.created_links,
            [CreatedLink {
                alias: "lenovo-1".to_owned(),
                link: VXLAN_LINK_NAME.to_owned(),
            }]
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
            created_links: Vec::new(),
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
            created_links: Vec::new(),
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
