//! D13.b — shared secure-exposure plumbing for service-hosting
//! roles (`nas`, `llm`).
//!
//! Canonical design:
//! `documents/operations/active/NodeRoleTaxonomyExtension_2026-06-11.md` §5
//! (six fail-closed rules) and §8 (controls E1–E4). This module is
//! the one hardened path both sibling services ride; the per-role
//! crates (`rustynet-nas`, `rustynet-llm-gateway`) never implement
//! their own exposure, identity, or authorisation logic.
//!
//! What lives here (pure, deterministic, transport-agnostic):
//!
//! - **E1 — tunnel-only bind validation.** A service listener may
//!   bind only an address of the mesh tunnel interface. `0.0.0.0`,
//!   loopback, LAN, and public binds are rejected fail-closed at
//!   startup. (The LLM *inference engine* is the inverse: loopback
//!   only — see [`validate_loopback_only_bind`].)
//! - **E2 — default-deny per-peer service authorisation.** Every
//!   new session is gated through
//!   `ContextualPolicySet::evaluate_with_membership` with the
//!   service's [`TrafficContext`]; empty/missing policy denies.
//! - **Daemon-mediated identity handoff.** The sibling service
//!   receives a [`VerifiedPeerIdentity`] the daemon resolved from
//!   the authenticated tunnel source address against signed
//!   membership state — never from client-supplied headers/keys.
//! - **Fail-closed health gating + E3 teardown-before-revoke.**
//!   [`ServiceExposureController`] is a deterministic state machine:
//!   sessions are only admitted in `Serving`; a health failure
//!   closes admission; capability revocation may complete only
//!   after every in-flight session has been severed
//!   ([`ServiceExposureController::capability_release_ready`]).
//! - **Service-access audit events** carrying ids/thumbprints/counts
//!   only — never tokens, file contents, prompts, or completions.

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;

use rustynet_control::membership::{MembershipNodeStatus, MembershipState};
use rustynet_control::roles::RoleCapability;
use rustynet_policy::{
    ContextualAccessRequest, ContextualPolicySet, Decision, MembershipDirectory, Protocol,
    TrafficContext,
};

/// The application-layer services a node can expose over the
/// tunnel. Distinct from `role_presets::ServiceKind`, which is the
/// sibling-binary deploy/undeploy vocabulary (and includes `relay`,
/// which has no per-session application gate).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ExposedService {
    Nas,
    Llm,
}

impl ExposedService {
    /// Stable wire string for IPC and audit logs.
    pub fn as_str(self) -> &'static str {
        match self {
            ExposedService::Nas => "nas",
            ExposedService::Llm => "llm",
        }
    }

    /// The policy context gating sessions to this service.
    pub fn traffic_context(self) -> TrafficContext {
        match self {
            ExposedService::Nas => TrafficContext::NasService,
            ExposedService::Llm => TrafficContext::LlmService,
        }
    }

    /// The signed membership capability advertising this service.
    pub fn capability(self) -> RoleCapability {
        match self {
            ExposedService::Nas => RoleCapability::ServesNas,
            ExposedService::Llm => RoleCapability::ServesLlm,
        }
    }
}

impl fmt::Display for ExposedService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Fail-closed error vocabulary for the exposure path. Every variant
/// is a refusal — there is no degrade-to-open branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceExposureError {
    /// E1: the requested listener bind is not a tunnel address
    /// (unspecified/loopback/LAN/public, or simply not one of the
    /// overlay addresses). The service must refuse to start.
    NonTunnelBind { requested: IpAddr, reason: String },
    /// The engine-side bind must be loopback only (LLM inference
    /// engine); anything else is refused at startup.
    NonLoopbackEngineBind { requested: IpAddr },
    /// The tunnel source address does not map to any active node in
    /// signed membership — no identity, no session.
    UnknownPeerAddress { source: IpAddr },
    /// Session admission attempted outside the `Serving` phase.
    NotServing { phase: &'static str },
    /// E2: signed policy did not produce `Decision::Allow` for the
    /// peer/service pair.
    PolicyDenied {
        peer_node_id: String,
        service: ExposedService,
    },
    /// E3: capability release was requested while sessions are
    /// still active — the revocation sequence must sever them first.
    SessionsStillActive { count: usize },
    /// State-machine transition not valid from the current phase.
    InvalidTransition {
        from: &'static str,
        attempted: &'static str,
    },
}

impl fmt::Display for ServiceExposureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceExposureError::NonTunnelBind { requested, reason } => write!(
                f,
                "service listener bind {requested} refused (tunnel-only, fail-closed): {reason}"
            ),
            ServiceExposureError::NonLoopbackEngineBind { requested } => write!(
                f,
                "inference engine bind {requested} refused (loopback-only, fail-closed)"
            ),
            ServiceExposureError::UnknownPeerAddress { source } => write!(
                f,
                "tunnel source {source} has no active signed-membership identity; session refused"
            ),
            ServiceExposureError::NotServing { phase } => {
                write!(
                    f,
                    "service not in Serving phase (phase={phase}); session refused"
                )
            }
            ServiceExposureError::PolicyDenied {
                peer_node_id,
                service,
            } => write!(
                f,
                "signed policy denies peer {peer_node_id} for service {service}; session refused"
            ),
            ServiceExposureError::SessionsStillActive { count } => write!(
                f,
                "capability release blocked: {count} session(s) still active (teardown precedes revocation)"
            ),
            ServiceExposureError::InvalidTransition { from, attempted } => {
                write!(f, "invalid exposure transition {from} -> {attempted}")
            }
        }
    }
}

impl std::error::Error for ServiceExposureError {}

// ---------------------------------------------------------------
// E1 — bind validation
// ---------------------------------------------------------------

/// Validate a service listener bind address against the node's
/// tunnel (overlay) addresses. Returns the address on success;
/// every other shape is a fail-closed startup error. There is no
/// LAN-bind escape hatch for service-hosting roles.
pub fn validate_tunnel_only_bind(
    requested: IpAddr,
    tunnel_addrs: &[IpAddr],
) -> Result<IpAddr, ServiceExposureError> {
    if requested.is_unspecified() {
        return Err(ServiceExposureError::NonTunnelBind {
            requested,
            reason: "wildcard bind (0.0.0.0/::) exposes the service beyond the tunnel".to_owned(),
        });
    }
    if requested.is_loopback() {
        return Err(ServiceExposureError::NonTunnelBind {
            requested,
            reason: "loopback bind is unreachable for mesh peers; the mesh-facing listener \
                     must bind the tunnel address"
                .to_owned(),
        });
    }
    if requested.is_multicast() {
        return Err(ServiceExposureError::NonTunnelBind {
            requested,
            reason: "multicast bind is not a valid service endpoint".to_owned(),
        });
    }
    if !tunnel_addrs.contains(&requested) {
        return Err(ServiceExposureError::NonTunnelBind {
            requested,
            reason: "address is not one of the node's tunnel addresses (LAN/public bind \
                     refused)"
                .to_owned(),
        });
    }
    Ok(requested)
}

/// Validate the inference-engine bind address: loopback only. The
/// engine must never be reachable from the tunnel or the LAN; only
/// the gateway (which performs identity + policy gating) talks to it.
pub fn validate_loopback_only_bind(requested: IpAddr) -> Result<IpAddr, ServiceExposureError> {
    if requested.is_loopback() {
        Ok(requested)
    } else {
        Err(ServiceExposureError::NonLoopbackEngineBind { requested })
    }
}

// ---------------------------------------------------------------
// Daemon-mediated peer identity
// ---------------------------------------------------------------

/// Identity the daemon hands to a sibling service for one session.
/// Derived from the authenticated tunnel source address resolved
/// against signed membership — the sibling service must treat this
/// as the only identity source and ignore any client-supplied
/// identity material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPeerIdentity {
    pub node_id: String,
    pub overlay_addr: IpAddr,
}

/// Resolve a tunnel source address to a verified peer identity.
/// `overlay_addr_to_node` is built by the daemon from signed state
/// (membership + signed address assignments) — never from runtime
/// claims. Unknown source ⇒ fail-closed.
pub fn resolve_peer_identity(
    source: IpAddr,
    overlay_addr_to_node: &BTreeMap<IpAddr, String>,
) -> Result<VerifiedPeerIdentity, ServiceExposureError> {
    match overlay_addr_to_node.get(&source) {
        Some(node_id) => Ok(VerifiedPeerIdentity {
            node_id: node_id.clone(),
            overlay_addr: source,
        }),
        None => Err(ServiceExposureError::UnknownPeerAddress { source }),
    }
}

// ---------------------------------------------------------------
// E2 — default-deny service access evaluation
// ---------------------------------------------------------------

/// Evaluate whether `peer_node_id` may open a session to
/// `host_node_id`'s service. One enforcement point: every new
/// session goes through here; the engine's `Decision::Deny` default
/// covers the empty/missing-policy cases, and rules with an empty
/// `contexts` list never match service contexts (rustynet-policy
/// `context_matches`).
pub fn evaluate_service_access(
    policy: &ContextualPolicySet,
    membership: &MembershipDirectory,
    peer_node_id: &str,
    host_node_id: &str,
    service: ExposedService,
) -> Decision {
    policy.evaluate_with_membership(
        &ContextualAccessRequest {
            src: format!("node:{peer_node_id}"),
            dst: format!("node:{host_node_id}"),
            protocol: Protocol::Tcp,
            context: service.traffic_context(),
        },
        membership,
    )
}

// ---------------------------------------------------------------
// Signed-membership view (no self-promotion)
// ---------------------------------------------------------------

/// What the signed bundle says THIS node serves. The daemon reads
/// its own capability set from verified membership state on
/// bootstrap and reload; local config cannot grant a service
/// capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ServiceHostingView {
    pub serves_nas: bool,
    pub serves_llm: bool,
}

impl ServiceHostingView {
    pub fn serves(self, service: ExposedService) -> bool {
        match service {
            ExposedService::Nas => self.serves_nas,
            ExposedService::Llm => self.serves_llm,
        }
    }
}

/// Derive the service-hosting view for `self_node_id` from signed
/// membership state. Fail-closed: an absent or non-active node
/// serves nothing.
pub fn service_hosting_view_from_membership(
    state: &MembershipState,
    self_node_id: &str,
) -> ServiceHostingView {
    state
        .nodes
        .iter()
        .find(|node| node.node_id == self_node_id && node.status == MembershipNodeStatus::Active)
        .map(|node| ServiceHostingView {
            serves_nas: node.capabilities.contains(&RoleCapability::ServesNas),
            serves_llm: node.capabilities.contains(&RoleCapability::ServesLlm),
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------
// Exposure state machine (health gate + E3 teardown-before-revoke)
// ---------------------------------------------------------------

/// Lifecycle phase of an exposed service endpoint. Transitions are
/// deterministic and validated; there is no path that admits a
/// session outside `Serving`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExposurePhase {
    /// Sibling service not deployed (or undeployed). Admits nobody.
    NotDeployed,
    /// Deployed but health not yet verified. Admits nobody —
    /// deploy-before-advertise means the capability must not be
    /// advertised from this phase either.
    AwaitingHealth,
    /// Healthy and serving. The only phase that admits sessions.
    Serving { healthy_since_unix: u64 },
    /// Health check failed. Listener admission closed (fail-closed),
    /// never degraded to unmediated mode.
    Degraded { reason: String },
    /// Capability revocation in progress: admission closed, in-flight
    /// sessions being severed.
    Revoking,
    /// All sessions severed and listener closed. Only now may the
    /// capability leave local state (E3).
    TornDown,
}

impl ExposurePhase {
    fn name(&self) -> &'static str {
        match self {
            ExposurePhase::NotDeployed => "not_deployed",
            ExposurePhase::AwaitingHealth => "awaiting_health",
            ExposurePhase::Serving { .. } => "serving",
            ExposurePhase::Degraded { .. } => "degraded",
            ExposurePhase::Revoking => "revoking",
            ExposurePhase::TornDown => "torn_down",
        }
    }
}

/// Monotonic per-controller session identifier.
pub type SessionId = u64;

/// Deterministic controller for one exposed service on this node.
/// The daemon owns one per service-hosting capability; the sibling
/// service reports health into it and consults it for admission.
#[derive(Debug)]
pub struct ServiceExposureController {
    service: ExposedService,
    phase: ExposurePhase,
    active_sessions: BTreeMap<SessionId, VerifiedPeerIdentity>,
    next_session_id: SessionId,
}

impl ServiceExposureController {
    pub fn new(service: ExposedService) -> Self {
        Self {
            service,
            phase: ExposurePhase::NotDeployed,
            active_sessions: BTreeMap::new(),
            next_session_id: 1,
        }
    }

    pub fn service(&self) -> ExposedService {
        self.service
    }

    pub fn phase(&self) -> &ExposurePhase {
        &self.phase
    }

    pub fn phase_name(&self) -> &'static str {
        self.phase.name()
    }

    pub fn active_session_count(&self) -> usize {
        self.active_sessions.len()
    }

    /// Sibling service deployed (unit installed + started). Health
    /// is not yet verified, so nothing is admitted and the signed
    /// capability must not be advertised yet.
    pub fn mark_deployed(&mut self) -> Result<(), ServiceExposureError> {
        match self.phase {
            ExposurePhase::NotDeployed => {
                self.phase = ExposurePhase::AwaitingHealth;
                Ok(())
            }
            _ => Err(ServiceExposureError::InvalidTransition {
                from: self.phase.name(),
                attempted: "mark_deployed",
            }),
        }
    }

    /// Health verified OK. Valid from `AwaitingHealth` (initial
    /// verification — this is the deploy-before-advertise gate) and
    /// from `Degraded` (recovery). `Serving` refreshes are no-ops.
    pub fn report_health_ok(&mut self, now_unix: u64) -> Result<(), ServiceExposureError> {
        match self.phase {
            ExposurePhase::AwaitingHealth | ExposurePhase::Degraded { .. } => {
                self.phase = ExposurePhase::Serving {
                    healthy_since_unix: now_unix,
                };
                Ok(())
            }
            ExposurePhase::Serving { .. } => Ok(()),
            _ => Err(ServiceExposureError::InvalidTransition {
                from: self.phase.name(),
                attempted: "report_health_ok",
            }),
        }
    }

    /// Health check failed (process wedged, storage unmounted, model
    /// unloaded, accelerator gone…). Admission closes immediately
    /// and fail-closed; already-established sessions are owned by
    /// the sibling process and are severed by the revocation path or
    /// the process exit, not silently kept admitting.
    pub fn report_health_failure(&mut self, reason: impl Into<String>) {
        // Health failure is accepted from any deployed phase; from
        // Revoking/TornDown the stricter state already admits nobody.
        if matches!(
            self.phase,
            ExposurePhase::AwaitingHealth
                | ExposurePhase::Serving { .. }
                | ExposurePhase::Degraded { .. }
        ) {
            self.phase = ExposurePhase::Degraded {
                reason: reason.into(),
            };
        }
    }

    /// Whether the signed bundle may advertise this service's
    /// capability for this host right now (deploy-before-advertise:
    /// only a verified-healthy service is advertised).
    pub fn advertisement_permitted(&self) -> bool {
        matches!(self.phase, ExposurePhase::Serving { .. })
    }

    /// Admit a new session for an identity the daemon verified and a
    /// policy decision the caller obtained from
    /// [`evaluate_service_access`]. This is the single admission
    /// point: not `Serving` ⇒ refuse; decision != Allow ⇒ refuse.
    pub fn admit_session(
        &mut self,
        peer: VerifiedPeerIdentity,
        decision: Decision,
    ) -> Result<SessionId, ServiceExposureError> {
        if !matches!(self.phase, ExposurePhase::Serving { .. }) {
            return Err(ServiceExposureError::NotServing {
                phase: self.phase.name(),
            });
        }
        if decision != Decision::Allow {
            return Err(ServiceExposureError::PolicyDenied {
                peer_node_id: peer.node_id,
                service: self.service,
            });
        }
        let id = self.next_session_id;
        self.next_session_id = self.next_session_id.saturating_add(1);
        self.active_sessions.insert(id, peer);
        Ok(id)
    }

    /// Session ended (peer disconnect, natural close, or severance
    /// executed by the sibling service).
    pub fn close_session(&mut self, id: SessionId) -> bool {
        self.active_sessions.remove(&id).is_some()
    }

    /// Re-evaluate every active session against current signed
    /// policy (called on each policy/membership update). Returns the
    /// sessions whose peers are no longer allowed — the caller must
    /// sever them immediately and then `close_session` each (E2/E4:
    /// revocation is immediate, a session can never outlive its
    /// authorisation).
    pub fn sessions_to_sever_after_policy_change(
        &self,
        mut still_allowed: impl FnMut(&VerifiedPeerIdentity) -> Decision,
    ) -> Vec<SessionId> {
        self.active_sessions
            .iter()
            .filter(|(_, peer)| still_allowed(peer) != Decision::Allow)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Begin capability revocation: admission closes now, and the
    /// returned session ids must be severed by the caller. The
    /// capability must NOT leave local state yet.
    pub fn begin_revocation(&mut self) -> Vec<SessionId> {
        self.phase = ExposurePhase::Revoking;
        self.active_sessions.keys().copied().collect()
    }

    /// Complete the teardown after every session has been severed
    /// and closed. Fails closed while any session remains — this is
    /// the E3 enforcement point: `capability_release_ready` only
    /// becomes true through here.
    pub fn confirm_torn_down(&mut self) -> Result<(), ServiceExposureError> {
        if !matches!(self.phase, ExposurePhase::Revoking) {
            return Err(ServiceExposureError::InvalidTransition {
                from: self.phase.name(),
                attempted: "confirm_torn_down",
            });
        }
        if !self.active_sessions.is_empty() {
            return Err(ServiceExposureError::SessionsStillActive {
                count: self.active_sessions.len(),
            });
        }
        self.phase = ExposurePhase::TornDown;
        Ok(())
    }

    /// E3: the signed revocation (dropping `serves_nas`/`serves_llm`
    /// from local state) may proceed only when this returns true.
    pub fn capability_release_ready(&self) -> bool {
        matches!(self.phase, ExposurePhase::TornDown)
    }

    /// Sibling service undeployed after revocation completed.
    pub fn mark_undeployed(&mut self) -> Result<(), ServiceExposureError> {
        match self.phase {
            ExposurePhase::TornDown => {
                self.phase = ExposurePhase::NotDeployed;
                Ok(())
            }
            _ => Err(ServiceExposureError::InvalidTransition {
                from: self.phase.name(),
                attempted: "mark_undeployed",
            }),
        }
    }
}

// ---------------------------------------------------------------
// Audit events (ids / thumbprints / counts only)
// ---------------------------------------------------------------

/// One service-access audit event. Carries identifiers and
/// thumbprints only — never tokens, prompts, completions, file
/// names, or file contents (secret-hygiene baseline).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceAccessEvent {
    pub unix_ts: u64,
    pub service: ExposedService,
    pub peer_node_id: String,
    pub allowed: bool,
    pub session_id: Option<SessionId>,
    /// Short hash thumbprint of any in-band session token involved;
    /// never the token itself.
    pub token_thumbprint: Option<String>,
}

impl fmt::Display for ServiceAccessEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ts={} service={} peer={} decision={}",
            self.unix_ts,
            self.service,
            self.peer_node_id,
            if self.allowed { "allow" } else { "deny" },
        )?;
        if let Some(id) = self.session_id {
            write!(f, " session={id}")?;
        }
        if let Some(thumb) = &self.token_thumbprint {
            write!(f, " token_thumbprint={thumb}")?;
        }
        Ok(())
    }
}
