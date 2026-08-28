//! CN-4 of `CrossNetworkSubstrateIntegrationSpec_2026-06-21.md` §0.4: the
//! Tier-C slirp substrate, over the existing `RemoteShellHost` seam.
//!
//! WHAT THE SPEC ASKED THIS TIER TO PROVE. §3: "Tier C (slirp) = cross-OS smoke
//! only. Windows/macOS behind slirp `Shared` NAT (**type not selectable**).
//! Requires a UTM quit/relaunch (config-plist constraint)." §5 Phase X4:
//! "Cross-OS traversal + relay-fallback smoke only." So the tier's job is to
//! establish that the cross-OS guests really are behind the emulator's shared
//! NAT and to let the traversal/relay smoke run there — NOT to shape a NAT
//! profile, which UTM does not expose a control for.
//!
//! WHERE THE SPEC'S FRAMING IS STALE, AND WHAT THIS IMPLEMENTS INSTEAD.
//! §4.2's slirp arm is written against `live_linux_lab_orchestrator.sh`, which
//! no longer exists (§0.5 "Dead sections"), and it prescribes "return a
//! documented SKIP with a clear 'requires UTM relaunch' reason" — a skip that
//! asserted nothing. Under the landed CN-1/CN-2 seam a substrate is a typed
//! provider with `setup`/`teardown`/`supports`/`apply_nat_profile`, so the
//! faithful minimum is a provider that:
//!
//! 1. **provisions no overlay** — slirp NAT is configured in the VM's own
//!    hypervisor settings before boot, so there is nothing for this process to
//!    create on the guest, and `topology_level_seam()` keeps answering
//!    `NoOverlay` for the selector. The handle records the participants and
//!    `provisioned: false`, so teardown has nothing to remove and can never
//!    report a pass over residue it invented;
//! 2. **verifies the claim it is named for** — each participating guest's
//!    default route must actually go via a slirp/user-mode gateway, so a run
//!    labelled "cross-OS behind shared NAT" cannot silently be a run of
//!    bridged guests on one flat LAN. An unverifiable guest fails the setup
//!    closed rather than being excluded;
//! 3. **claims no NAT profile at all** — the shared NAT's type is not
//!    selectable from inside the guest, so every profile is a reasoned
//!    `UnsupportedByDesign` and `apply_nat_profile` is a typed refusal. This is
//!    the honest answer: claiming, say, `port_restricted_cone` because slirp
//!    happens to behave like one would make the NAT-matrix evidence assert a
//!    profile nothing selected or enforced.
//!
//! Leaf ops are argv-only through [`NetLeafRunner`], exactly as the other two
//! substrates (AGENTS.md §4).

use std::collections::BTreeMap;

use super::substrate::{
    CrossNetworkSubstrateProvider, NatApplyError, NatModifiers, NatProfileId, NetLeafRunner,
    SiteRef, SubstrateHandle, SubstrateRecord, SubstrateSetupFailure, SubstrateTopology, Support,
    topology_digest,
};

/// The gateway QEMU/UTM user-mode ("slirp", UTM `Shared Network`) hands every
/// guest. QEMU's user-mode stack numbers the virtual network 10.0.2.0/24 with
/// the gateway at `.2`; UTM inherits it unchanged.
pub const SLIRP_GATEWAY: &str = "10.0.2.2";
/// The virtual network the same stack puts the guest on.
pub const SLIRP_NETWORK_PREFIX: &str = "10.0.2.";

/// The Tier-C slirp provider.
///
/// It owns no kernel objects: the NAT it is named for belongs to the
/// hypervisor, not to the guest. What it owns is the ASSERTION that the NAT is
/// there, which is the only thing about this tier that can be wrong silently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlirpSubstrateProvider {
    participants: Vec<String>,
}

impl SlirpSubstrateProvider {
    /// Build a provider over the aliases expected to sit behind slirp.
    ///
    /// An empty list is refused: a substrate that verifies nothing would report
    /// a pass for every topology, including one with no slirp guest in it.
    pub fn new(participants: Vec<String>) -> Result<Self, String> {
        if participants.is_empty() {
            return Err(
                "slirp substrate needs at least one participating node alias to verify".to_owned(),
            );
        }
        let mut seen = std::collections::BTreeSet::new();
        for alias in &participants {
            if alias.trim().is_empty() {
                return Err("slirp participant alias must not be empty".to_owned());
            }
            if !seen.insert(alias.clone()) {
                return Err(format!("duplicate slirp participant alias {alias:?}"));
            }
        }
        Ok(Self { participants })
    }

    pub fn participants(&self) -> &[String] {
        &self.participants
    }

    fn handle(&self, topology: &SubstrateTopology) -> SubstrateHandle {
        SubstrateHandle {
            record: SubstrateRecord {
                substrate_id: self.id().to_owned(),
                topology_digest: topology_digest(self.id(), topology, None),
                // Deliberately false: this substrate creates nothing, so
                // teardown must have nothing to remove. Recording `true` would
                // make a resumed run look for residue that never existed and
                // fail closed on its absence.
                provisioned: false,
                participants: self.participants.clone(),
            },
            // No overlay: the guest's slirp address is what it already has, and
            // `SubstrateHandle::endpoint()` therefore answers on the underlay
            // plane for every alias, leaving `ctx.endpoints` untouched.
            overlay_ips: BTreeMap::new(),
            underlay_ips: topology
                .nodes
                .iter()
                .map(|(alias, ip)| (alias.clone(), ip.to_string()))
                .collect(),
            created_resources: Vec::new(),
        }
    }

    /// Assert one guest really is behind the emulator's shared NAT.
    ///
    /// Fails CLOSED on every ambiguity: a transport failure, a non-zero exit,
    /// and an unparseable route are all refusals, because "I could not read the
    /// default route" must never read as "the guest is behind slirp".
    fn verify_slirp_egress(runner: &dyn NetLeafRunner, alias: &str) -> Result<String, String> {
        let output = runner
            .run(&["ip", "-4", "route", "show", "default"])
            .map_err(|err| format!("{alias}: reading the default route failed: {err}"))?;
        if !output.success {
            return Err(format!(
                "{alias}: reading the default route failed: {}",
                output.stderr.trim()
            ));
        }
        let gateway = parse_default_gateway(&output.stdout).ok_or_else(|| {
            format!(
                "{alias}: could not parse a default gateway out of {:?}; refusing to assume the \
                 guest is behind slirp",
                output.stdout.trim()
            )
        })?;
        if gateway != SLIRP_GATEWAY {
            return Err(format!(
                "{alias}: default gateway is {gateway}, not the slirp/user-mode gateway \
                 {SLIRP_GATEWAY}; this guest is not behind UTM 'Shared Network' NAT (the \
                 hypervisor setting is applied before boot and needs a UTM relaunch to change)"
            ));
        }
        Ok(gateway)
    }
}

/// `ip -4 route show default` prints `default via 10.0.2.2 dev enp0s1 …`.
fn parse_default_gateway(stdout: &str) -> Option<String> {
    for line in stdout.lines() {
        let mut tokens = line.split_whitespace();
        if tokens.next() != Some("default") {
            continue;
        }
        if tokens.next() != Some("via") {
            continue;
        }
        if let Some(gateway) = tokens.next()
            && gateway.parse::<std::net::Ipv4Addr>().is_ok()
        {
            return Some(gateway.to_owned());
        }
    }
    None
}

impl CrossNetworkSubstrateProvider for SlirpSubstrateProvider {
    fn id(&self) -> &'static str {
        "slirp"
    }

    /// NOTHING is claimed, and that is the honest answer rather than a gap.
    ///
    /// UTM's `Shared Network` NAT type is not selectable — there is no setting,
    /// no in-guest control, and no argv this substrate could run to change it.
    /// Claiming the profile slirp happens to resemble would make NAT-matrix
    /// evidence assert a profile that nothing selected and nothing enforces,
    /// which is precisely the false pass `Support` exists to prevent.
    fn supports(&self, profile: &NatProfileId) -> Support {
        Support::UnsupportedByDesign(format!(
            "the slirp tier runs cross-OS guests behind UTM 'Shared Network' NAT, whose type is \
             not selectable from inside the guest; it proves cross-OS traversal and relay \
             fallback under whatever the emulator provides and shapes no profile, so it cannot \
             claim '{profile}'"
        ))
    }

    fn supports_with_modifiers(
        &self,
        profile: &NatProfileId,
        _modifiers: &NatModifiers,
    ) -> Support {
        // The profile is already out of reach, so the modifier answer cannot
        // be more permissive than the profile answer.
        self.supports(profile)
    }

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
                "cannot apply '{profile}' to slirp site '{site}': the emulator owns this NAT and \
                 its type is fixed at VM configuration time (a change needs a UTM quit and \
                 relaunch), so there is no in-guest apply path to take"
            ),
        )))
    }

    /// Provisions nothing; VERIFIES that each participant is behind slirp.
    fn setup(
        &self,
        topology: &SubstrateTopology,
        runners: &BTreeMap<String, &dyn NetLeafRunner>,
    ) -> Result<SubstrateHandle, Box<SubstrateSetupFailure>> {
        let handle = self.handle(topology);
        let fail = |message: String| {
            Box::new(SubstrateSetupFailure {
                message,
                partial: handle.clone(),
            })
        };
        for alias in &self.participants {
            let Some(runner) = runners.get(alias).copied() else {
                return Err(fail(format!(
                    "no leaf runner for slirp participant '{alias}'"
                )));
            };
            if let Err(err) = Self::verify_slirp_egress(runner, alias) {
                return Err(fail(err));
            }
        }
        Ok(handle)
    }

    /// Nothing was created, so nothing is removed — and the honest way to say
    /// that is an unconditional `Ok`, not a sweep that could "succeed" at
    /// finding nothing and be mistaken for proof of cleanliness.
    fn teardown(
        &self,
        _handle: &SubstrateHandle,
        _runners: &BTreeMap<String, &dyn NetLeafRunner>,
    ) -> Result<(), String> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::substrate::mock::MockLeafRunner;
    use super::*;
    use std::net::Ipv4Addr;

    fn topology(pairs: &[(&str, &str)]) -> SubstrateTopology {
        SubstrateTopology {
            nodes: pairs
                .iter()
                .map(|(alias, ip)| {
                    (
                        (*alias).to_owned(),
                        (*ip).parse::<Ipv4Addr>().expect("test ip"),
                    )
                })
                .collect(),
        }
    }

    fn runner_map<'a>(
        runners: &[(&str, &'a MockLeafRunner)],
    ) -> BTreeMap<String, &'a dyn NetLeafRunner> {
        runners
            .iter()
            .map(|(alias, runner)| ((*alias).to_owned(), *runner as &dyn NetLeafRunner))
            .collect()
    }

    fn slirp_route_runner() -> MockLeafRunner {
        MockLeafRunner {
            stdout_by_match: vec![(
                "route show default".to_owned(),
                "default via 10.0.2.2 dev enp0s1 proto dhcp metric 100\n".to_owned(),
            )],
            ..MockLeafRunner::default()
        }
    }

    #[test]
    fn slirp_claims_no_nat_profile_and_explains_why() {
        let provider = SlirpSubstrateProvider::new(vec!["win-1".to_owned()]).expect("provider");
        for name in super::super::substrate::KNOWN_NAT_PROFILES {
            let support = provider.supports(&NatProfileId::parse(name).expect("known"));
            assert!(!support.is_supported(), "{name} must not be claimed");
            assert!(
                support.reason().expect("reason").contains("not selectable"),
                "{name} refusal must state that the NAT type is not selectable"
            );
        }
    }

    #[test]
    fn slirp_setup_verifies_every_participant_is_behind_the_shared_nat() {
        let win = slirp_route_runner();
        let mac = slirp_route_runner();
        let runners = runner_map(&[("win-1", &win), ("mac-1", &mac)]);
        let handle = SlirpSubstrateProvider::new(vec!["win-1".to_owned(), "mac-1".to_owned()])
            .expect("provider")
            .setup(
                &topology(&[("win-1", "192.168.64.30"), ("mac-1", "192.168.64.31")]),
                &runners,
            )
            .expect("both guests are behind slirp");
        assert!(
            !handle.record.provisioned,
            "the slirp substrate creates nothing, so it must not record a provisioned overlay"
        );
        assert!(handle.overlay_ips.is_empty());
        assert!(handle.created_resources.is_empty());
        assert_eq!(win.recorded().len(), 1, "one route read per participant");
        assert_eq!(mac.recorded().len(), 1);
    }

    /// A bridged guest reaches the same validators over the same SSH, so the
    /// only thing standing between "cross-OS behind shared NAT" and a run that
    /// silently proves nothing of the sort is this assertion.
    #[test]
    fn slirp_setup_fails_closed_when_a_guest_is_not_behind_slirp() {
        let bridged = MockLeafRunner {
            stdout_by_match: vec![(
                "route show default".to_owned(),
                "default via 192.168.64.1 dev enp0s1 proto dhcp metric 100\n".to_owned(),
            )],
            ..MockLeafRunner::default()
        };
        let runners = runner_map(&[("win-1", &bridged)]);
        let failure = SlirpSubstrateProvider::new(vec!["win-1".to_owned()])
            .expect("provider")
            .setup(&topology(&[("win-1", "192.168.64.30")]), &runners)
            .expect_err("a bridged guest must fail the slirp substrate closed");
        assert!(
            failure.message.contains("192.168.64.1")
                && failure.message.contains("not behind UTM 'Shared Network'"),
            "{}",
            failure.message
        );
    }

    /// Unreadable is NOT the same as absent: a guest whose route we could not
    /// read must fail, never pass by omission.
    #[test]
    fn slirp_setup_fails_closed_on_an_unreadable_or_unparseable_route() {
        for runner in [
            MockLeafRunner {
                transport_error_on: vec![0],
                ..MockLeafRunner::default()
            },
            MockLeafRunner {
                fail_on: vec![0],
                failure_stderr: "Operation not permitted".to_owned(),
                ..MockLeafRunner::default()
            },
            // Exit 0, empty output — the shape a guest with no default route
            // produces, and the one an "assume slirp" implementation would pass.
            MockLeafRunner::default(),
        ] {
            let runners = runner_map(&[("win-1", &runner)]);
            let failure = SlirpSubstrateProvider::new(vec!["win-1".to_owned()])
                .expect("provider")
                .setup(&topology(&[("win-1", "192.168.64.30")]), &runners)
                .expect_err("an unverifiable guest must fail closed");
            assert!(failure.message.contains("win-1"), "{}", failure.message);
        }
    }

    #[test]
    fn slirp_apply_nat_profile_is_a_typed_refusal_that_touches_no_guest() {
        let runner = slirp_route_runner();
        let runners = runner_map(&[("win-1", &runner)]);
        let provider = SlirpSubstrateProvider::new(vec!["win-1".to_owned()]).expect("provider");
        let mut handle = provider.handle(&topology(&[("win-1", "192.168.64.30")]));
        let err = provider
            .apply_nat_profile(
                &mut handle,
                &SiteRef::new("win-1").expect("site"),
                &NatProfileId::parse("full_cone").expect("known"),
                &NatModifiers::none(),
                &runners,
            )
            .expect_err("slirp cannot shape a profile");
        assert!(matches!(err, NatApplyError::Refused(_)), "{err:?}");
        assert!(err.message().contains("UTM quit and relaunch"), "{err}");
        assert!(
            runner.recorded().is_empty(),
            "a refusal must not touch the guest"
        );
    }

    #[test]
    fn slirp_teardown_removes_nothing_because_it_created_nothing() {
        let runner = slirp_route_runner();
        let runners = runner_map(&[("win-1", &runner)]);
        let provider = SlirpSubstrateProvider::new(vec!["win-1".to_owned()]).expect("provider");
        let handle = provider.handle(&topology(&[("win-1", "192.168.64.30")]));
        provider
            .teardown(&handle, &runners)
            .expect("no-op teardown");
        assert!(runner.recorded().is_empty());
    }

    #[test]
    fn slirp_provider_refuses_an_empty_or_duplicated_participant_list() {
        assert!(SlirpSubstrateProvider::new(Vec::new()).is_err());
        assert!(
            SlirpSubstrateProvider::new(vec!["a".to_owned(), "a".to_owned()])
                .expect_err("duplicate aliases must be refused")
                .contains("duplicate")
        );
    }

    #[test]
    fn default_gateway_parsing_ignores_non_default_and_malformed_lines() {
        assert_eq!(
            parse_default_gateway("default via 10.0.2.2 dev enp0s1\n").as_deref(),
            Some(SLIRP_GATEWAY)
        );
        assert_eq!(
            parse_default_gateway("10.0.2.0/24 dev enp0s1 scope link"),
            None
        );
        assert_eq!(parse_default_gateway("default dev enp0s1 scope link"), None);
        assert_eq!(
            parse_default_gateway("default via not-an-ip dev enp0s1"),
            None
        );
        assert!(SLIRP_GATEWAY.starts_with(SLIRP_NETWORK_PREFIX));
    }
}
