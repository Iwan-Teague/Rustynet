//! Managed-DNS handoff decision (D-6b, design §5.5, §5.1).
//!
//! This module is the control-plane decision point that decides whether a
//! client's managed-DNS resolver assignment hands out the RustyDNS mesh
//! endpoint. It consumes the post-reconcile [`TandemTogglePhase`] produced by
//! [`crate::tandem_dns::reconcile`] plus the abstract inputs the phase-1
//! state machine already models (scope, exit assignment, readiness
//! observation) and one additional abstract input: the RustyDNS mesh
//! endpoint itself.
//!
//! Fail-closed posture (design §5.1, invariant 7): while signed desired state
//! is ON but any trust, readiness, assignment, or endpoint condition fails,
//! the decision is [`ManagedDnsHandoffDecision::Contained`] — selected DNS is
//! deliberately unavailable and the reason is surfaced. It is never a
//! fallback to a non-tandem or pre-tunnel resolver; the blocker follows the
//! device. Signed OFF (and the prepare-only phases, which never grant client
//! use) restore the ordinary Rustynet DNS posture, expressed here as
//! [`ManagedDnsHandoffDecision::NoHandoff`].
//!
//! Endpoint carriage status (flagged, owner-gated): no signed wire-format
//! object in the repository today carries the RustyDNS mesh address
//! (`ServiceCapabilityV1.mesh_address` in design §5.3 is design-only, and
//! `ManagedDnsAssignmentV1` in §5.5 is not yet implemented). Defining a new
//! signed wire-format field is an owner/security-gated decision of the same
//! class as the blind-relay §16 gate and the phase-1 prepare-intent wire
//! format gate (phase-1 notes §3.2). Accordingly this module consumes the
//! endpoint as an abstract [`ManagedDnsEndpoint`] input and validates it
//! against the signed mesh assignment range supplied by the caller; the
//! signed carriage decision does not block this control-plane wiring.
//!
//! This module is domain-layer and transport-agnostic: it imports no backend,
//! WireGuard, OS, or process-management types, performs no I/O, and never
//! decides the exit-side port-53 redirect (D-6c, out of scope).

use crate::tandem_dns::{
    ExitAssignment, ReadinessObservation, TandemMode, TandemReasonCode, TandemScope,
    TandemTogglePhase,
};

/// The only resolver port in the v1 tandem contract (design §5.3: `dns_port`
/// is exactly 53; transports are exactly `{udp, tcp}`).
pub const TANDEM_DNS_RESOLVER_PORT: u16 = 53;

/// Signed mesh assignment range used to contain the advertised endpoint.
///
/// Design §5.3 requires the capability `mesh_address` to be the exact signed
/// mesh IPv4 address of the exit with "no LAN/public/loopback inference", and
/// §5.4 rejects "an address outside the signed mesh assignment". The mesh
/// range itself is signed network configuration, so the caller supplies it
/// here and this module refuses any endpoint that is not strictly inside it.
///
/// Construction is fail-closed: a prefix length above 32 and a network
/// address with host bits set are both rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeshIpv4Prefix {
    network: std::net::Ipv4Addr,
    prefix_len: u8,
}

impl MeshIpv4Prefix {
    /// Builds a mesh prefix, rejecting a prefix length above 32 and a
    /// network address whose host bits are not zero.
    pub const fn new(network: std::net::Ipv4Addr, prefix_len: u8) -> Option<Self> {
        if prefix_len > 32 {
            return None;
        }
        let bits = network.to_bits();
        let host_mask: u32 = if prefix_len == 0 {
            u32::MAX
        } else if prefix_len == 32 {
            0
        } else {
            u32::MAX >> prefix_len
        };
        if bits & host_mask != 0 {
            return None;
        }
        Some(Self {
            network,
            prefix_len,
        })
    }

    /// The validated network address.
    pub fn network(&self) -> std::net::Ipv4Addr {
        self.network
    }

    /// The validated prefix length.
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Whether `addr` is inside this prefix (membership only; the network
    /// address itself is inside).
    pub const fn contains(&self, addr: std::net::Ipv4Addr) -> bool {
        let network_mask = if self.prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix_len as u32)
        };
        (self.network.to_bits() ^ addr.to_bits()) & network_mask == 0
    }
}

/// Abstract RustyDNS mesh endpoint handed to a selected client (design §5.5).
///
/// V1 carries only the resolver mesh IPv4 address: the port is fixed at
/// [`TANDEM_DNS_RESOLVER_PORT`] and the transports are fixed at
/// `{udp, tcp}` by the signed capability contract (design §5.3). The
/// address must be inside the caller-supplied signed mesh range;
/// [`managed_dns_handoff_decision`] enforces that containment, so a loopback,
/// link-local, or LAN address can never be advertised as the resolver.
///
/// This is an abstract domain input, not a wire format: how the address
/// reaches the client reducer inside signed state is the owner-gated
/// carriage decision flagged in the module docs and the phase-2 notes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagedDnsEndpoint {
    mesh_address: std::net::Ipv4Addr,
}

impl ManagedDnsEndpoint {
    /// Builds an endpoint for the given mesh address. Address-class rules are
    /// enforced at decision time against the signed mesh range, not here, so
    /// construction stays total.
    pub fn new(mesh_address: std::net::Ipv4Addr) -> Self {
        Self { mesh_address }
    }

    /// The resolver mesh address.
    pub fn mesh_address(&self) -> std::net::Ipv4Addr {
        self.mesh_address
    }

    /// The fixed v1 resolver port.
    pub fn port(&self) -> u16 {
        TANDEM_DNS_RESOLVER_PORT
    }
}

/// Inputs to one client's managed-DNS handoff decision.
///
/// `scope` is the client selector from the accepted signed policy
/// (design §5.4). `None` means no accepted policy is known to this reducer,
/// which fails closed if the phase claims the ON family. `endpoint` is the
/// abstract RustyDNS mesh endpoint; `None` means the endpoint is unknown or
/// not carried in accepted signed state, which contains rather than falls
/// back.
#[derive(Debug, Clone, Copy)]
pub struct ManagedDnsHandoffInput<'a> {
    /// Post-reconcile tandem phase for this exit/network.
    pub phase: TandemTogglePhase,
    /// Client selector from the accepted signed policy, if one is accepted.
    pub scope: Option<&'a TandemScope>,
    /// This client's NodeId.
    pub client_node_id: &'a str,
    /// Proof that this client's active signed exit is the policy's exit.
    pub exit_assignment: ExitAssignment,
    /// Abstract RustyDNS mesh endpoint input (carriage owner-gated; see
    /// module docs).
    pub endpoint: Option<ManagedDnsEndpoint>,
    /// The signed mesh assignment range the endpoint must fall inside.
    pub mesh_prefix: Option<MeshIpv4Prefix>,
    /// Authenticated readiness observation for the RustyDNS service.
    pub readiness: ReadinessObservation,
}

/// The resolver-assignment outcome for one client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedDnsHandoffDecision {
    /// Hand the RustyDNS mesh endpoint to the client as its managed mesh
    /// resolver. `mode` is the signed tandem mode in force; both v1 modes
    /// hand off the same endpoint (the redirect variant only adds the
    /// exit-side port-53 diversion, which is D-6c and not decided here).
    Handoff {
        endpoint: ManagedDnsEndpoint,
        mode: TandemMode,
    },
    /// Selected DNS is deliberately unavailable: signed desired state is ON
    /// but a trust, readiness, assignment, or endpoint condition failed.
    /// The reason is surfaced to the operator; this never degrades to a
    /// non-tandem resolver (design invariant 7).
    Contained { reason: TandemReasonCode },
    /// No tandem resolver assignment applies: signed OFF, a prepare-only
    /// phase that cannot advertise a resolver, or draining (new handoffs
    /// are gone). The ordinary Rustynet DNS posture applies.
    NoHandoff,
}

/// Decides one client's managed-DNS resolver assignment from signed tandem
/// state plus the abstract endpoint/readiness inputs.
///
/// The check order is deterministic and fail-closed; earlier arms win:
///
/// 1. Signed OFF or residue error: no assignment.
/// 2. Prepare-only phases (`PreparingContained`, `Prepared`): no assignment
///    — a prepare intent is authorization to prepare local contained state
///    only and "cannot advertise a resolver" (design §5.2).
/// 3. `Draining`: no new handoffs (design §5.1).
/// 4. `RuntimeContained`: already contained; the recorded reason is carried.
/// 5. `Active`: every predicate must hold — accepted scope present, this
///    client selected, exit assignment proven, readiness ready, endpoint
///    present and inside the signed mesh range — otherwise the client is
///    contained with the first failing predicate's reason code.
pub fn managed_dns_handoff_decision(
    input: ManagedDnsHandoffInput<'_>,
) -> ManagedDnsHandoffDecision {
    match &input.phase {
        TandemTogglePhase::Off | TandemTogglePhase::ResidueError => {
            ManagedDnsHandoffDecision::NoHandoff
        }
        TandemTogglePhase::PreparingContained | TandemTogglePhase::Prepared => {
            ManagedDnsHandoffDecision::NoHandoff
        }
        TandemTogglePhase::Draining => ManagedDnsHandoffDecision::NoHandoff,
        TandemTogglePhase::RuntimeContained { reason, .. } => {
            ManagedDnsHandoffDecision::Contained { reason: *reason }
        }
        TandemTogglePhase::Active(mode) => active_phase_decision(input, *mode),
    }
}

/// Active-phase predicate ladder. Every failure contains; nothing falls back.
fn active_phase_decision(
    input: ManagedDnsHandoffInput<'_>,
    mode: TandemMode,
) -> ManagedDnsHandoffDecision {
    let scope = match input.scope {
        Some(scope) => scope,
        // ON-family phase with no accepted signed policy known: fail closed.
        None => {
            return ManagedDnsHandoffDecision::Contained {
                reason: TandemReasonCode::SignedPolicyInvalid,
            };
        }
    };

    // A malformed client identity can never be matched against a signed
    // selector; contain rather than guess.
    if input.client_node_id.trim().is_empty() {
        return ManagedDnsHandoffDecision::Contained {
            reason: TandemReasonCode::UnknownClient,
        };
    }

    // Readiness first: an unready service must not be handed out even if
    // other predicates would also fail, so the surfaced reason is the
    // service health, not a selector artifact.
    if let Some(reason) = input.readiness.contain_reason() {
        return ManagedDnsHandoffDecision::Contained { reason };
    }

    // Selection: which clients does the signed policy name for this exit?
    let selected = match scope {
        TandemScope::AllClientsUsingExit => {
            // All clients using this exit are selected, but invariant 3
            // still requires proof that this client's active signed exit is
            // that exit; unknown proof fails closed.
            matches!(input.exit_assignment, ExitAssignment::ProvenSameExit)
        }
        TandemScope::NodeIds(ids) => {
            if !ids.iter().any(|id| id == input.client_node_id) {
                // Not selected by the signed policy: the ordinary (non-tandem)
                // posture applies to this client. This is not containment.
                return ManagedDnsHandoffDecision::NoHandoff;
            }
            // Selected by NodeId: the same-exit proof is still mandatory.
            matches!(input.exit_assignment, ExitAssignment::ProvenSameExit)
        }
    };
    if !selected {
        return ManagedDnsHandoffDecision::Contained {
            reason: TandemReasonCode::AssignmentMismatch,
        };
    }

    // Endpoint must be known (carried in accepted signed state) and provably
    // inside the signed mesh assignment range. Unknown contains as
    // unreachable; unprovable containment contains as assignment mismatch
    // (design §5.4 rejects an address outside the signed mesh assignment).
    let endpoint = match input.endpoint {
        Some(endpoint) => endpoint,
        None => {
            return ManagedDnsHandoffDecision::Contained {
                reason: TandemReasonCode::RustydnsUnreachable,
            };
        }
    };
    let prefix = match input.mesh_prefix {
        Some(prefix) => prefix,
        None => {
            return ManagedDnsHandoffDecision::Contained {
                reason: TandemReasonCode::AssignmentMismatch,
            };
        }
    };
    if !prefix.contains(endpoint.mesh_address()) {
        return ManagedDnsHandoffDecision::Contained {
            reason: TandemReasonCode::AssignmentMismatch,
        };
    }

    ManagedDnsHandoffDecision::Handoff { endpoint, mode }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tandem_dns::{TandemMode, TandemReasonCode};

    const MESH: MeshIpv4Prefix =
        match MeshIpv4Prefix::new(std::net::Ipv4Addr::new(100, 64, 0, 0), 10) {
            Some(p) => p,
            None => panic!("valid const prefix"),
        };

    fn endpoint() -> ManagedDnsEndpoint {
        ManagedDnsEndpoint::new(std::net::Ipv4Addr::new(100, 64, 0, 7))
    }

    fn input<'a>(
        phase: TandemTogglePhase,
        scope: &'a TandemScope,
        client: &'a str,
    ) -> ManagedDnsHandoffInput<'a> {
        ManagedDnsHandoffInput {
            phase,
            scope: Some(scope),
            client_node_id: client,
            exit_assignment: ExitAssignment::ProvenSameExit,
            endpoint: Some(endpoint()),
            mesh_prefix: Some(MESH),
            readiness: ReadinessObservation::Ready,
        }
    }

    #[test]
    fn active_managed_ready_hands_out_mesh_ip() {
        let scope = TandemScope::AllClientsUsingExit;
        let decision = managed_dns_handoff_decision(input(
            TandemTogglePhase::Active(TandemMode::Managed),
            &scope,
            "client-1",
        ));
        assert_eq!(
            decision,
            ManagedDnsHandoffDecision::Handoff {
                endpoint: endpoint(),
                mode: TandemMode::Managed,
            }
        );
    }

    #[test]
    fn active_managed_redirect_hands_out_same_endpoint_with_mode() {
        let scope = TandemScope::AllClientsUsingExit;
        let decision = managed_dns_handoff_decision(input(
            TandemTogglePhase::Active(TandemMode::ManagedRedirect),
            &scope,
            "client-1",
        ));
        assert_eq!(
            decision,
            ManagedDnsHandoffDecision::Handoff {
                endpoint: endpoint(),
                mode: TandemMode::ManagedRedirect,
            }
        );
    }

    #[test]
    fn active_with_unready_service_is_contained_not_default() {
        let scope = TandemScope::AllClientsUsingExit;
        let mut inp = input(
            TandemTogglePhase::Active(TandemMode::Managed),
            &scope,
            "client-1",
        );
        inp.readiness = ReadinessObservation::NotReady(TandemReasonCode::UpstreamUnready);
        assert_eq!(
            managed_dns_handoff_decision(inp),
            ManagedDnsHandoffDecision::Contained {
                reason: TandemReasonCode::UpstreamUnready,
            }
        );
    }

    #[test]
    fn active_with_unknown_endpoint_is_contained_not_fallback() {
        let scope = TandemScope::AllClientsUsingExit;
        let mut inp = input(
            TandemTogglePhase::Active(TandemMode::Managed),
            &scope,
            "client-1",
        );
        inp.endpoint = None;
        assert_eq!(
            managed_dns_handoff_decision(inp),
            ManagedDnsHandoffDecision::Contained {
                reason: TandemReasonCode::RustydnsUnreachable,
            }
        );
    }

    #[test]
    fn active_with_stale_readiness_contains_with_staleness_code() {
        let scope = TandemScope::AllClientsUsingExit;
        let mut inp = input(
            TandemTogglePhase::Active(TandemMode::Managed),
            &scope,
            "client-1",
        );
        inp.readiness = ReadinessObservation::Stale;
        assert_eq!(
            managed_dns_handoff_decision(inp),
            ManagedDnsHandoffDecision::Contained {
                reason: TandemReasonCode::ControlStaleWarning,
            }
        );
    }

    #[test]
    fn active_with_unauthenticated_readiness_contains() {
        let scope = TandemScope::AllClientsUsingExit;
        let mut inp = input(
            TandemTogglePhase::Active(TandemMode::Managed),
            &scope,
            "client-1",
        );
        inp.readiness = ReadinessObservation::Unauthenticated;
        assert_eq!(
            managed_dns_handoff_decision(inp),
            ManagedDnsHandoffDecision::Contained {
                reason: TandemReasonCode::LocalAuthFailed,
            }
        );
    }

    #[test]
    fn active_with_incompatible_readiness_contains_passthrough_code() {
        let scope = TandemScope::AllClientsUsingExit;
        let mut inp = input(
            TandemTogglePhase::Active(TandemMode::Managed),
            &scope,
            "client-1",
        );
        inp.readiness = ReadinessObservation::Incompatible(TandemReasonCode::ProtocolIncompatible);
        assert_eq!(
            managed_dns_handoff_decision(inp),
            ManagedDnsHandoffDecision::Contained {
                reason: TandemReasonCode::ProtocolIncompatible,
            }
        );
    }

    #[test]
    fn off_means_no_handoff() {
        let scope = TandemScope::AllClientsUsingExit;
        assert_eq!(
            managed_dns_handoff_decision(input(TandemTogglePhase::Off, &scope, "client-1")),
            ManagedDnsHandoffDecision::NoHandoff
        );
    }

    #[test]
    fn draining_means_no_new_handoff() {
        let scope = TandemScope::AllClientsUsingExit;
        assert_eq!(
            managed_dns_handoff_decision(input(TandemTogglePhase::Draining, &scope, "client-1")),
            ManagedDnsHandoffDecision::NoHandoff
        );
    }

    #[test]
    fn residue_error_means_no_handoff() {
        let scope = TandemScope::AllClientsUsingExit;
        assert_eq!(
            managed_dns_handoff_decision(input(
                TandemTogglePhase::ResidueError,
                &scope,
                "client-1"
            )),
            ManagedDnsHandoffDecision::NoHandoff
        );
    }

    #[test]
    fn prepare_only_phases_never_advertise_resolver() {
        let scope = TandemScope::AllClientsUsingExit;
        for phase in [
            TandemTogglePhase::PreparingContained,
            TandemTogglePhase::Prepared,
        ] {
            assert_eq!(
                managed_dns_handoff_decision(input(phase, &scope, "client-1")),
                ManagedDnsHandoffDecision::NoHandoff
            );
        }
    }

    #[test]
    fn runtime_contained_carries_recorded_reason() {
        let scope = TandemScope::AllClientsUsingExit;
        let phase = TandemTogglePhase::RuntimeContained {
            reason: TandemReasonCode::SignedPolicyExpired,
            desired_mode: TandemMode::Managed,
        };
        assert_eq!(
            managed_dns_handoff_decision(input(phase, &scope, "client-1")),
            ManagedDnsHandoffDecision::Contained {
                reason: TandemReasonCode::SignedPolicyExpired,
            }
        );
    }

    #[test]
    fn active_without_accepted_scope_fails_closed() {
        let scope = TandemScope::AllClientsUsingExit;
        let mut inp = input(
            TandemTogglePhase::Active(TandemMode::Managed),
            &scope,
            "client-1",
        );
        inp.scope = None;
        assert_eq!(
            managed_dns_handoff_decision(inp),
            ManagedDnsHandoffDecision::Contained {
                reason: TandemReasonCode::SignedPolicyInvalid,
            }
        );
    }

    #[test]
    fn empty_client_id_is_contained_as_unknown_client() {
        let scope = TandemScope::AllClientsUsingExit;
        assert_eq!(
            managed_dns_handoff_decision(input(
                TandemTogglePhase::Active(TandemMode::Managed),
                &scope,
                "   "
            )),
            ManagedDnsHandoffDecision::Contained {
                reason: TandemReasonCode::UnknownClient,
            }
        );
    }

    #[test]
    fn node_ids_scope_selects_only_listed_clients() {
        let scope = TandemScope::NodeIds(vec!["client-2".to_string(), "client-1".to_string()]);
        assert_eq!(
            managed_dns_handoff_decision(input(
                TandemTogglePhase::Active(TandemMode::Managed),
                &scope,
                "client-1"
            )),
            ManagedDnsHandoffDecision::Handoff {
                endpoint: endpoint(),
                mode: TandemMode::Managed,
            }
        );
        // An unlisted client is not selected; its ordinary posture applies.
        assert_eq!(
            managed_dns_handoff_decision(input(
                TandemTogglePhase::Active(TandemMode::Managed),
                &scope,
                "client-9"
            )),
            ManagedDnsHandoffDecision::NoHandoff
        );
    }

    #[test]
    fn all_clients_scope_requires_proven_same_exit() {
        let scope = TandemScope::AllClientsUsingExit;
        for assignment in [ExitAssignment::ProvenMismatch, ExitAssignment::Unknown] {
            let mut inp = input(
                TandemTogglePhase::Active(TandemMode::Managed),
                &scope,
                "client-1",
            );
            inp.exit_assignment = assignment;
            assert_eq!(
                managed_dns_handoff_decision(inp),
                ManagedDnsHandoffDecision::Contained {
                    reason: TandemReasonCode::AssignmentMismatch,
                }
            );
        }
    }

    #[test]
    fn node_ids_selected_client_still_requires_proven_same_exit() {
        let scope = TandemScope::NodeIds(vec!["client-1".to_string()]);
        let mut inp = input(
            TandemTogglePhase::Active(TandemMode::Managed),
            &scope,
            "client-1",
        );
        inp.exit_assignment = ExitAssignment::Unknown;
        assert_eq!(
            managed_dns_handoff_decision(inp),
            ManagedDnsHandoffDecision::Contained {
                reason: TandemReasonCode::AssignmentMismatch,
            }
        );
    }

    #[test]
    fn endpoint_outside_signed_mesh_range_is_contained() {
        let scope = TandemScope::AllClientsUsingExit;
        let mut inp = input(
            TandemTogglePhase::Active(TandemMode::Managed),
            &scope,
            "client-1",
        );
        // Loopback: banned by invariant 4 and outside the mesh range.
        inp.endpoint = Some(ManagedDnsEndpoint::new(std::net::Ipv4Addr::LOCALHOST));
        assert_eq!(
            managed_dns_handoff_decision(inp),
            ManagedDnsHandoffDecision::Contained {
                reason: TandemReasonCode::AssignmentMismatch,
            }
        );
        // RFC1918 LAN class: also outside the signed mesh range.
        inp.endpoint = Some(ManagedDnsEndpoint::new(std::net::Ipv4Addr::new(
            192, 168, 1, 10,
        )));
        assert_eq!(
            managed_dns_handoff_decision(inp),
            ManagedDnsHandoffDecision::Contained {
                reason: TandemReasonCode::AssignmentMismatch,
            }
        );
    }

    #[test]
    fn missing_mesh_prefix_fails_closed() {
        let scope = TandemScope::AllClientsUsingExit;
        let mut inp = input(
            TandemTogglePhase::Active(TandemMode::Managed),
            &scope,
            "client-1",
        );
        inp.mesh_prefix = None;
        assert_eq!(
            managed_dns_handoff_decision(inp),
            ManagedDnsHandoffDecision::Contained {
                reason: TandemReasonCode::AssignmentMismatch,
            }
        );
    }

    #[test]
    fn readiness_precedes_selector_and_endpoint_reasons() {
        let scope = TandemScope::AllClientsUsingExit;
        let mut inp = input(
            TandemTogglePhase::Active(TandemMode::Managed),
            &scope,
            "client-1",
        );
        inp.readiness = ReadinessObservation::NotReady(TandemReasonCode::BlocklistUnready);
        inp.endpoint = None;
        assert_eq!(
            managed_dns_handoff_decision(inp),
            ManagedDnsHandoffDecision::Contained {
                reason: TandemReasonCode::BlocklistUnready,
            }
        );
    }

    #[test]
    fn mesh_prefix_rejects_bad_construction() {
        assert!(MeshIpv4Prefix::new(std::net::Ipv4Addr::new(100, 64, 0, 0), 33).is_none());
        // Host bits set: 100.64.0.1/10 is not a valid network address.
        assert!(MeshIpv4Prefix::new(std::net::Ipv4Addr::new(100, 64, 0, 1), 10).is_none());
    }

    #[test]
    fn mesh_prefix_contains_boundary_addresses() {
        let p = MeshIpv4Prefix::new(std::net::Ipv4Addr::new(100, 64, 0, 0), 10).expect("valid");
        assert!(p.contains(std::net::Ipv4Addr::new(100, 64, 0, 0)));
        assert!(p.contains(std::net::Ipv4Addr::new(100, 127, 255, 254)));
        assert!(!p.contains(std::net::Ipv4Addr::new(100, 128, 0, 0)));
        assert!(!p.contains(std::net::Ipv4Addr::new(100, 63, 255, 255)));
        // /32 and /0 extremes.
        let host = MeshIpv4Prefix::new(std::net::Ipv4Addr::new(100, 64, 0, 7), 32).expect("valid");
        assert!(host.contains(std::net::Ipv4Addr::new(100, 64, 0, 7)));
        assert!(!host.contains(std::net::Ipv4Addr::new(100, 64, 0, 8)));
        let everywhere = MeshIpv4Prefix::new(std::net::Ipv4Addr::UNSPECIFIED, 0).expect("valid");
        assert!(everywhere.contains(std::net::Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn endpoint_port_is_fixed_v1_53() {
        assert_eq!(endpoint().port(), 53);
        assert_eq!(TANDEM_DNS_RESOLVER_PORT, 53);
    }
}
