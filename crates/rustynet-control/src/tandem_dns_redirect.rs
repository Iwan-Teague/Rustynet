//! Tandem DNS transparent `:53` redirect decision (D-6c, control plane).
//!
//! Pure, transport-agnostic decision over the tandem toggle state machine
//! ([`tandem_dns::TandemTogglePhase`]): when the tandem mode is
//! `ON/managed_redirect` on an exit hosting rustydns and the service is
//! ready, the exit's default-deny NAT layer must DNAT-redirect the selected
//! clients' outbound plain DNS (UDP/TCP dport 53, any destination except the
//! mesh rustydns service itself) to the local rustydns `:53`. Every other
//! phase produces NO redirect rule.
//!
//! Fail-closed contract (design §5.1/§7.2/§10.7):
//! - `contained` phases (`RuntimeContained`, `Draining`, `ResidueError`,
//!   `PreparingContained`, `Off`) never generate a redirect NOR the DoT/DoH
//!   egress block: the base DNS-fail-closed posture still blocks plain DNS,
//!   so the redirect's absence must never open a plaintext escape. The
//!   [`TandemDnsRedirectDecision::ContainNoRedirect`] variant names that
//!   explicit posture so callers cannot conflate "no redirect, DNS
//!   deliberately unavailable" with "no redirect, and DNS leaks".
//! - The redirect is ADDITIVE to the base exit NAT/killswitch: the returned
//!   spec carries its own generation scope and service endpoint, disjoint
//!   from the base NAT tables; teardown removes exactly the redirect rules
//!   (no residue, release-blocking per §10.7).
//! - While the redirect is ACTIVE the policy additionally carries the
//!   DoT/DoH egress block (owner decision 3, digest entry 27, DEFAULT-ON,
//!   not opt-in): block DoT (`:853` tcp+udp) and the pinned
//!   [`KNOWN_DOH_RESOLVER_IPS`] on `:443` for the selected sources, except
//!   the sanctioned tunnel path to the mesh resolver. KNOWN MECHANISM
//!   LIMIT: DoH-over-`:443` to an arbitrary host is indistinguishable from
//!   HTTPS without SNI inspection — "block all DoH" is unachievable by any
//!   IP-list mechanism; the residual is documented and owned by an
//!   SNI-inspection follow-up, not left open by choice.
//!
//! No I/O, no backend/WireGuard types: the Linux nft renderer consumes the
//! returned spec (`crates/rustynetd/src/linux_tandem_dns_redirect.rs`).
//! macOS pf and Windows WFP dataplanes are flagged follow-ups (design
//! §9.2/§9.3); this module is the single source of the decision.

use crate::managed_dns_handoff::{ManagedDnsEndpoint, MeshIpv4Prefix};
use crate::tandem_dns::{
    ExitAssignment, ReadinessObservation, TandemMode, TandemReasonCode, TandemScope,
    TandemTogglePhase,
};

/// DNS of the transparent redirect: plain DNS (`:53`) only.
pub const TANDEM_DNS_REDIRECT_PORT: u16 = 53;

/// DNS-over-TLS port blocked while the tandem redirect is active (owner
/// decision 3, `OwnerDecisionDigest_2026-08-27.md` entry 27): a client that
/// cannot speak plain `:53` will otherwise silently fall back to DoT and
/// leak DNS off-mesh. The mesh rustydns service itself is exempt (the
/// sanctioned tunnel path).
pub const TANDEM_DNS_DOT_PORT: u16 = 853;

/// HTTPS port of the known-DoH-endpoint block. Blocked ONLY for the pinned
/// [`KNOWN_DOH_RESOLVER_IPS`] set — never for `:443` in general.
pub const TANDEM_DNS_DOH_BLOCK_PORT: u16 = 443;

/// Version stamp of the named, versioned known-DoH-endpoint set. Bump when
/// [`KNOWN_DOH_RESOLVER_IPS`] changes so rendered evidence can name exactly
/// which revision of the list a dataplane enforced.
pub const KNOWN_DOH_RESOLVER_IPS_VERSION: &str = "2026-08-29.1";

/// The named, versioned set of well-known public DoH resolver IPv4
/// addresses blocked while the tandem redirect is active (owner decision 3).
/// IPs, not SNI: this closes the well-known-public-resolver case (the
/// overwhelming majority of client DoH). ARBITRARY self-hosted DoH over
/// `:443` is a documented KNOWN MECHANISM LIMIT — indistinguishable from
/// HTTPS without SNI inspection — tracked as an SNI-inspection follow-up,
/// NOT an open door left by choice.
///
/// Pinned and const so every renderer (Linux nft, macOS pf) and every test
/// enforces byte-identical sets; order is significant (deterministic
/// rendering).
pub const KNOWN_DOH_RESOLVER_IPS: [std::net::Ipv4Addr; 8] = [
    // Cloudflare
    std::net::Ipv4Addr::new(1, 1, 1, 1),
    std::net::Ipv4Addr::new(1, 0, 0, 1),
    // Google Public DNS
    std::net::Ipv4Addr::new(8, 8, 8, 8),
    std::net::Ipv4Addr::new(8, 8, 4, 4),
    // Quad9
    std::net::Ipv4Addr::new(9, 9, 9, 9),
    std::net::Ipv4Addr::new(149, 112, 112, 112),
    // Cisco OpenDNS
    std::net::Ipv4Addr::new(208, 67, 222, 222),
    std::net::Ipv4Addr::new(208, 67, 220, 220),
];

/// The DoT/DoH egress-block policy carried by an active redirect. Owner
/// decision 3 ratified this as DEFAULT-ON whenever the tandem redirect is
/// active: a false positive fails CLOSED (breaks visibly, recoverable), a
/// false negative fails OPEN (silent DNS leak), so blocking is not opt-in.
///
/// The layer is INSEPARABLE from the redirect: renderers install it in the
/// same generation-scoped table/anchor and the decision bridge refuses to
/// render any redirect that does not carry this policy (fail-closed — a
/// redirect without the layer would be a silent policy gap, not a partial
/// install).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TandemDnsEgressBlockPolicy {
    /// Block outbound DoT (`:853` tcp+udp) from the selected sources except
    /// the sanctioned tunnel path to the mesh resolver.
    pub block_dot: bool,
    /// The exact known-DoH-endpoint IP set to block on `:443`. Renderers
    /// must refuse any value that is not exactly [`KNOWN_DOH_RESOLVER_IPS`]
    /// (the policy is versioned and pinned; a mismatch is a bug, not a
    /// configuration).
    pub doh_endpoint_ips: Vec<std::net::Ipv4Addr>,
    /// [`KNOWN_DOH_RESOLVER_IPS_VERSION`] the set was built from, carried so
    /// evidence can name the revision.
    pub doh_endpoint_ips_version: &'static str,
}

impl TandemDnsEgressBlockPolicy {
    /// The one sanctioned policy: DoT blocked, the pinned known-DoH set
    /// blocked. Constructing anything else is refused downstream.
    pub fn always_on() -> Self {
        Self {
            block_dot: true,
            doh_endpoint_ips: KNOWN_DOH_RESOLVER_IPS.to_vec(),
            doh_endpoint_ips_version: KNOWN_DOH_RESOLVER_IPS_VERSION,
        }
    }

    /// True iff this policy is exactly [`Self::always_on`] (the only policy
    /// renderers accept).
    pub fn is_canonical(&self) -> bool {
        *self == Self::always_on()
    }
}

/// Input to [`tandem_dns_redirect_decision`].
///
/// Mirrors [`crate::managed_dns_handoff::ManagedDnsHandoffInput`]: the same
/// runtime observations, evaluated for the redirect (not the handoff) rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TandemDnsRedirectInput<'a> {
    pub phase: &'a TandemTogglePhase,
    pub scope: Option<&'a TandemScope>,
    pub exit_assignment: ExitAssignment,
    pub readiness: &'a ReadinessObservation,
    /// Loopback-free mesh address of the rustydns service on THIS exit.
    pub endpoint: Option<ManagedDnsEndpoint>,
    pub mesh_prefix: Option<MeshIpv4Prefix>,
}

/// Redirect rule-generation decision.
///
/// `Redirect` carries everything the per-OS renderer needs: the generation-
/// scoped source selection and the exact service address. `NoRedirect` means
/// plain DNS stays blocked by the base fail-closed posture (never open).
/// `ContainNoRedirect` additionally names the active containment reason:
/// the base posture blocks DNS by design and the redirect must not be read
/// as the only thing preventing a leak.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TandemDnsRedirectDecision {
    /// Generate the generation-scoped DNAT redirect (Linux nft today).
    /// Only ever produced for `Active(TandemMode::ManagedRedirect)`.
    Redirect {
        mode: TandemMode,
        scope: TandemScope,
        service_address: std::net::Ipv4Addr,
        /// DoT/DoH egress block (owner decision 3): always the canonical
        /// default-on policy. Renderers refuse a non-canonical policy
        /// fail-closed.
        egress_block: TandemDnsEgressBlockPolicy,
    },
    /// No redirect rule. The base DNS-fail-closed posture still blocks plain
    /// DNS: this is the OFF/managed-without-redirect posture, not an open
    /// escape. `reason` is `None` for the unremarkable phases where a
    /// redirect is simply not part of the contract (`Off`, preparation
    /// phases, plain `managed` mode, `Draining`) and `Some` only when a
    /// specific closed-vocabulary condition explains the absence (e.g.
    /// `ResidueError` ⇒ [`TandemReasonCode::Residue`]).
    NoRedirect { reason: Option<TandemReasonCode> },
    /// No redirect rule AND the tandem containment posture is what keeps
    /// plain DNS blocked (DNS is deliberately unavailable for the selected
    /// scope). The absence of the redirect must never be mistaken for an
    /// open path.
    ContainNoRedirect { reason: TandemReasonCode },
}

/// Pure, total decision: the redirect rule spec, or its absence with reason.
///
/// Degradation ladder mirrors `managed_dns_handoff_decision` (validity →
/// assignment → readiness → endpoint/prefix → scope), fail-closed at every
/// step: anything that is not a proven-active `managed_redirect` phase with
/// a ready, resolvable, in-mesh service yields no redirect.
pub fn tandem_dns_redirect_decision(
    input: TandemDnsRedirectInput<'_>,
) -> TandemDnsRedirectDecision {
    use TandemDnsRedirectDecision as D;
    use TandemTogglePhase as P;

    match input.phase {
        // Not active: no redirect. `ResidueError` additionally blocks
        // re-enable upstream; `Off`/`PreparingContained`/`Prepared` have no
        // redirect by definition (mode is not managed_redirect yet).
        P::Off => D::NoRedirect { reason: None },
        P::ResidueError => D::NoRedirect {
            reason: Some(TandemReasonCode::Residue),
        },
        P::PreparingContained | P::Prepared => D::NoRedirect { reason: None },
        P::Draining => D::NoRedirect { reason: None },
        // Contained: containment (base fail-closed DNS posture) retained.
        P::RuntimeContained { reason, .. } => D::ContainNoRedirect { reason: *reason },
        P::Active(mode) => {
            // The redirect exists ONLY in managed_redirect mode. Plain
            // `managed` keeps the handoff (D-6b) and must NOT translate :53.
            if *mode != TandemMode::ManagedRedirect {
                return D::NoRedirect { reason: None };
            }
            // Scope must be carried by signed policy (no implicit fallback,
            // TDNS-19).
            let Some(scope) = input.scope else {
                return D::ContainNoRedirect {
                    reason: TandemReasonCode::SignedPolicyInvalid,
                };
            };
            // Readiness gates translation exactly like the handoff: a
            // not-ready service must never swallow client DNS.
            if let Some(reason) = input.readiness.contain_reason() {
                return D::ContainNoRedirect { reason };
            }
            if !matches!(input.readiness, ReadinessObservation::Ready) {
                return D::ContainNoRedirect {
                    reason: TandemReasonCode::RustydnsUnreachable,
                };
            }
            // A redirect with no concrete service address is refuse-to-
            // translate: DNAT to a guessed address would blackhole client
            // DNS.
            let Some(endpoint) = input.endpoint else {
                return D::ContainNoRedirect {
                    reason: TandemReasonCode::RustydnsUnreachable,
                };
            };
            // Service address must be inside the mesh prefix, or the DNAT
            // would point clients at an off-mesh host.
            match input.mesh_prefix {
                Some(prefix) if prefix.contains(endpoint.mesh_address()) => {}
                _ => {
                    return D::ContainNoRedirect {
                        reason: TandemReasonCode::AssignmentMismatch,
                    };
                }
            }
            // Proven exit assignment required for the redirect scope: a
            // redirect installed on the wrong exit would capture DNS that
            // the tandem exit never elected to serve.
            if input.exit_assignment != ExitAssignment::ProvenSameExit {
                return D::ContainNoRedirect {
                    reason: TandemReasonCode::AssignmentMismatch,
                };
            }
            D::Redirect {
                mode: *mode,
                scope: scope.clone(),
                service_address: endpoint.mesh_address(),
                egress_block: TandemDnsEgressBlockPolicy::always_on(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tandem_dns::{
        DesiredPolicy, TandemDesiredOn, TandemReasonCode as RC, TandemScope, TandemTogglePhase,
    };
    use std::net::Ipv4Addr;

    fn ready() -> ReadinessObservation {
        ReadinessObservation::Ready
    }

    fn active_redirect() -> TandemTogglePhase {
        TandemTogglePhase::Active(TandemMode::ManagedRedirect)
    }

    fn input<'a>(
        phase: &'a TandemTogglePhase,
        scope: Option<&'a TandemScope>,
        readiness: &'a ReadinessObservation,
        endpoint: Option<ManagedDnsEndpoint>,
        assignment: ExitAssignment,
    ) -> TandemDnsRedirectInput<'a> {
        TandemDnsRedirectInput {
            phase,
            scope,
            exit_assignment: assignment,
            readiness,
            endpoint,
            mesh_prefix: Some(MeshIpv4Prefix::new(Ipv4Addr::new(100, 64, 0, 0), 10).unwrap()),
        }
    }

    fn all_scope() -> TandemScope {
        TandemScope::AllClientsUsingExit
    }

    fn endpoint() -> Option<ManagedDnsEndpoint> {
        Some(ManagedDnsEndpoint::new(Ipv4Addr::new(100, 64, 0, 9)))
    }

    #[test]
    fn active_managed_redirect_with_ready_service_redirects() {
        let phase = active_redirect();
        let r = ready();
        let scope = all_scope();
        let decision = tandem_dns_redirect_decision(input(
            &phase,
            Some(&scope),
            &r,
            endpoint(),
            ExitAssignment::ProvenSameExit,
        ));
        assert_eq!(
            decision,
            TandemDnsRedirectDecision::Redirect {
                mode: TandemMode::ManagedRedirect,
                scope,
                service_address: Ipv4Addr::new(100, 64, 0, 9),
                egress_block: TandemDnsEgressBlockPolicy::always_on(),
            }
        );
    }

    /// Owner decision 3: an ACTIVE redirect always carries the canonical
    /// default-on DoT/DoH egress-block policy — the pinned named set, the
    /// pinned version stamp, DoT blocked.
    #[test]
    fn active_redirect_carries_canonical_dot_doh_block_policy() {
        let phase = active_redirect();
        let r = ready();
        let scope = all_scope();
        let decision = tandem_dns_redirect_decision(input(
            &phase,
            Some(&scope),
            &r,
            endpoint(),
            ExitAssignment::ProvenSameExit,
        ));
        let TandemDnsRedirectDecision::Redirect { egress_block, .. } = decision else {
            panic!("expected Redirect");
        };
        assert!(egress_block.block_dot);
        assert_eq!(egress_block.doh_endpoint_ips, KNOWN_DOH_RESOLVER_IPS);
        assert_eq!(
            egress_block.doh_endpoint_ips_version,
            KNOWN_DOH_RESOLVER_IPS_VERSION
        );
        assert!(egress_block.is_canonical());
    }

    /// The named, versioned DoH set is PINNED: any drift here must fail this
    /// test loudly rather than silently re-scoping what the dataplanes block.
    #[test]
    fn known_doh_resolver_ips_are_pinned() {
        assert_eq!(KNOWN_DOH_RESOLVER_IPS_VERSION, "2026-08-29.1");
        let rendered: Vec<String> = KNOWN_DOH_RESOLVER_IPS
            .iter()
            .map(|ip| ip.to_string())
            .collect();
        assert_eq!(
            rendered,
            vec![
                "1.1.1.1",
                "1.0.0.1", // Cloudflare
                "8.8.8.8",
                "8.8.4.4", // Google
                "9.9.9.9",
                "149.112.112.112", // Quad9
                "208.67.222.222",
                "208.67.220.220", // OpenDNS
            ]
        );
    }

    /// Fail-closed: nothing but the Redirect arm carries the egress-block
    /// policy — a contained/off posture must never render the DoT/DoH layer
    /// (the base fail-closed posture is the only DNS behavior there).
    #[test]
    fn non_redirect_arms_never_carry_egress_block_policy() {
        let r = ready();
        let scope = all_scope();
        let phases = [
            TandemTogglePhase::Off,
            TandemTogglePhase::RuntimeContained {
                reason: RC::ControlStaleWarning,
                desired_mode: TandemMode::ManagedRedirect,
            },
            TandemTogglePhase::Active(TandemMode::Managed),
        ];
        for phase in &phases {
            assert!(
                !matches!(
                    tandem_dns_redirect_decision(input(
                        phase,
                        Some(&scope),
                        &r,
                        endpoint(),
                        ExitAssignment::ProvenSameExit,
                    )),
                    TandemDnsRedirectDecision::Redirect { .. }
                ),
                "phase {phase:?} must not carry an egress-block policy"
            );
        }
    }

    #[test]
    fn plain_managed_mode_never_redirects() {
        let phase = TandemTogglePhase::Active(TandemMode::Managed);
        let r = ready();
        let scope = all_scope();
        assert_eq!(
            tandem_dns_redirect_decision(input(
                &phase,
                Some(&scope),
                &r,
                endpoint(),
                ExitAssignment::ProvenSameExit,
            )),
            TandemDnsRedirectDecision::NoRedirect { reason: None }
        );
    }

    #[test]
    fn off_and_residue_produce_no_redirect() {
        let r = ready();
        let scope = all_scope();
        for (phase, reason) in [
            (TandemTogglePhase::Off, None),
            (TandemTogglePhase::ResidueError, Some(RC::Residue)),
        ] {
            assert_eq!(
                tandem_dns_redirect_decision(input(
                    &phase,
                    Some(&scope),
                    &r,
                    endpoint(),
                    ExitAssignment::ProvenSameExit,
                )),
                TandemDnsRedirectDecision::NoRedirect { reason }
            );
        }
    }

    #[test]
    fn prepare_and_drain_produce_no_redirect() {
        let r = ready();
        let scope = all_scope();
        for phase in [
            TandemTogglePhase::PreparingContained,
            TandemTogglePhase::Prepared,
            TandemTogglePhase::Draining,
        ] {
            assert_eq!(
                tandem_dns_redirect_decision(input(
                    &phase,
                    Some(&scope),
                    &r,
                    endpoint(),
                    ExitAssignment::ProvenSameExit,
                )),
                TandemDnsRedirectDecision::NoRedirect { reason: None },
                "phase {phase:?}"
            );
        }
    }

    #[test]
    fn draining_absence_does_not_open_plain_dns() {
        // The redirect's absence during draining is NOT an escape: the base
        // DNS-fail-closed posture still blocks. Assert the posture naming so
        // a caller cannot render "no rule" as "pass through".
        let phase = TandemTogglePhase::Draining;
        let r = ready();
        let scope = all_scope();
        assert_eq!(
            tandem_dns_redirect_decision(input(
                &phase,
                Some(&scope),
                &r,
                endpoint(),
                ExitAssignment::ProvenSameExit,
            )),
            TandemDnsRedirectDecision::NoRedirect { reason: None }
        );
    }

    #[test]
    fn runtime_contained_names_containment_not_open_escape() {
        let phase = TandemTogglePhase::RuntimeContained {
            reason: RC::ControlStaleWarning,
            desired_mode: TandemMode::ManagedRedirect,
        };
        let r = ready();
        let scope = all_scope();
        assert_eq!(
            tandem_dns_redirect_decision(input(
                &phase,
                Some(&scope),
                &r,
                endpoint(),
                ExitAssignment::ProvenSameExit,
            )),
            TandemDnsRedirectDecision::ContainNoRedirect {
                reason: RC::ControlStaleWarning
            }
        );
    }

    #[test]
    fn missing_scope_is_contained_not_redirect() {
        let phase = active_redirect();
        let r = ready();
        assert_eq!(
            tandem_dns_redirect_decision(input(
                &phase,
                None,
                &r,
                endpoint(),
                ExitAssignment::ProvenSameExit,
            )),
            TandemDnsRedirectDecision::ContainNoRedirect {
                reason: RC::SignedPolicyInvalid
            }
        );
    }

    #[test]
    fn unready_service_is_contained_not_redirect() {
        let phase = active_redirect();
        let scope = all_scope();
        let readiness = ReadinessObservation::NotReady(RC::ListenerUnready);
        let expected_reason = readiness
            .contain_reason()
            .unwrap_or(TandemReasonCode::RustydnsUnreachable);
        assert_eq!(
            tandem_dns_redirect_decision(input(
                &phase,
                Some(&scope),
                &readiness,
                endpoint(),
                ExitAssignment::ProvenSameExit,
            )),
            TandemDnsRedirectDecision::ContainNoRedirect {
                reason: expected_reason
            }
        );
    }

    #[test]
    fn stale_or_unauthenticated_readiness_contained() {
        let phase = active_redirect();
        let scope = all_scope();
        for (observation, reason) in [
            (ReadinessObservation::Stale, RC::ControlStaleWarning),
            (ReadinessObservation::Unauthenticated, RC::LocalAuthFailed),
        ] {
            let readiness = observation;
            assert_eq!(
                tandem_dns_redirect_decision(input(
                    &phase,
                    Some(&scope),
                    &readiness,
                    endpoint(),
                    ExitAssignment::ProvenSameExit,
                )),
                TandemDnsRedirectDecision::ContainNoRedirect { reason }
            );
        }
    }

    #[test]
    fn missing_or_offmesh_endpoint_contained() {
        let phase = active_redirect();
        let r = ready();
        let scope = all_scope();
        // No endpoint at all: refuse to translate.
        assert_eq!(
            tandem_dns_redirect_decision(input(
                &phase,
                Some(&scope),
                &r,
                None,
                ExitAssignment::ProvenSameExit,
            )),
            TandemDnsRedirectDecision::ContainNoRedirect {
                reason: RC::RustydnsUnreachable
            }
        );
        // Endpoint outside the mesh prefix: would DNAT off-mesh.
        let offmesh = Some(ManagedDnsEndpoint::new(Ipv4Addr::new(192, 168, 1, 5)));
        assert_eq!(
            tandem_dns_redirect_decision(input(
                &phase,
                Some(&scope),
                &r,
                offmesh,
                ExitAssignment::ProvenSameExit,
            )),
            TandemDnsRedirectDecision::ContainNoRedirect {
                reason: RC::AssignmentMismatch
            }
        );
    }

    #[test]
    fn unproven_exit_assignment_contained() {
        let phase = active_redirect();
        let r = ready();
        let scope = all_scope();
        for assignment in [ExitAssignment::ProvenMismatch, ExitAssignment::Unknown] {
            assert_eq!(
                tandem_dns_redirect_decision(input(
                    &phase,
                    Some(&scope),
                    &r,
                    endpoint(),
                    assignment,
                )),
                TandemDnsRedirectDecision::ContainNoRedirect {
                    reason: RC::AssignmentMismatch
                },
                "assignment {assignment:?}"
            );
        }
    }

    #[test]
    fn node_scope_passes_through_on_redirect() {
        // A listed client scope survives into the spec; the renderer uses it
        // to build the generation-scoped selected source set.
        let phase = active_redirect();
        let r = ready();
        let scope = TandemScope::NodeIds(vec!["node-b".into(), "node-a".into()]);
        let decision = tandem_dns_redirect_decision(input(
            &phase,
            Some(&scope),
            &r,
            endpoint(),
            ExitAssignment::ProvenSameExit,
        ));
        match decision {
            TandemDnsRedirectDecision::Redirect { scope: s, .. } => {
                assert_eq!(s, scope);
            }
            other => panic!("expected Redirect, got {other:?}"),
        }
    }

    /// Sanity: the decision never returns a redirect for any non-redirect
    /// phase, exhaustively over the state machine.
    #[test]
    fn never_redirects_outside_active_managed_redirect() {
        let r = ready();
        let scope = all_scope();
        let phases = [
            TandemTogglePhase::Off,
            TandemTogglePhase::PreparingContained,
            TandemTogglePhase::Prepared,
            TandemTogglePhase::Draining,
            TandemTogglePhase::RuntimeContained {
                reason: RC::ControlStaleWarning,
                desired_mode: TandemMode::Managed,
            },
            TandemTogglePhase::ResidueError,
            TandemTogglePhase::Active(TandemMode::Managed),
        ];
        for phase in &phases {
            assert!(
                !matches!(
                    tandem_dns_redirect_decision(input(
                        phase,
                        Some(&scope),
                        &r,
                        endpoint(),
                        ExitAssignment::ProvenSameExit,
                    )),
                    TandemDnsRedirectDecision::Redirect { .. }
                ),
                "phase {phase:?} must not redirect"
            );
        }
    }

    /// The reconcile state machine and the redirect decision agree: whatever
    /// `reconcile` holds active in managed_redirect, the decision redirects;
    /// whatever it contains, the redirect is contained.
    #[test]
    fn agrees_with_reconcile_active_managed_redirect() {
        let desired = DesiredPolicy::On(TandemDesiredOn {
            mode: TandemMode::ManagedRedirect,
            exit_node_id: "exit-1".into(),
            scope: all_scope(),
        });
        let output = crate::tandem_dns::reconcile(
            &TandemTogglePhase::Off,
            &desired,
            crate::tandem_dns::PolicyValidity::Fresh,
            &ReadinessObservation::Ready,
            true,
            ExitAssignment::ProvenSameExit,
            false,
            false,
        );
        if let TandemTogglePhase::Active(mode) = output.next {
            let phase = TandemTogglePhase::Active(mode);
            let readiness = ReadinessObservation::Ready;
            assert!(matches!(
                tandem_dns_redirect_decision(input(
                    &phase,
                    Some(&all_scope()),
                    &readiness,
                    endpoint(),
                    ExitAssignment::ProvenSameExit,
                )),
                TandemDnsRedirectDecision::Redirect { .. }
            ));
        }
    }
}
