//! Node role taxonomy: nine user-selectable per-device presets.
//!
//! Canonical design:
//! `documents/operations/active/NodeRoleTaxonomy_2026-05-21.md` (base six),
//! extended by
//! `documents/operations/active/NodeRoleTaxonomyExtension_2026-06-11.md`
//! (the two service-hosting presets `nas` and `llm`) and by
//! `documents/operations/active/BlindRelayRoleDesign_2026-08-27.md`
//! (the privacy-preserving `blind_relay` preset, §4.2).
//!
//! Two-axis internal model (kept separate by design):
//!
//! - **Axis 1** — primary local role
//!   ([`PrimaryRole`]: `Admin | Client | BlindExit | BlindRelay`).
//!   Mirrors `crates/rustynetd/src/daemon.rs::NodeRole`. Controls local
//!   IPC permissions and dataplane posture.
//! - **Axis 2** — composable mesh capabilities ([`Capability`]).
//!   Signed in the membership bundle.
//!
//! Each user-facing preset ([`RolePreset`]) is a complete named
//! composition of one Axis-1 primary plus a fixed Axis-2 capability
//! set. [`ROLE_PRESET_TABLE`] is the authoritative mapping.
//!
//! Operator transitions between presets are validated against the
//! reversibility matrix in [`validate_transition`] /
//! [`transition_plan`]. Some transitions are local-only
//! (admin↔client); some require a signed membership update record;
//! some are irreversible (anything involving `blind_exit`); and
//! transitions that cross the blind-relay privacy boundary carry
//! [`TransitionPlan::requires_privacy_boundary_reinit`] — the
//! ordered teardown/purge/re-verify ceremony is a phase-4
//! deliverable (BlindRelayRoleDesign §6.1) and is NOT performed by
//! this layer.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

/// User-facing role preset. One per device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RolePreset {
    Client,
    Admin,
    Exit,
    BlindExit,
    Relay,
    Anchor,
    Nas,
    Llm,
    BlindRelay,
}

impl RolePreset {
    /// Stable wire string. Use for IPC, CLI args, audit logs.
    pub fn as_str(self) -> &'static str {
        match self {
            RolePreset::Client => "client",
            RolePreset::Admin => "admin",
            RolePreset::Exit => "exit",
            RolePreset::BlindExit => "blind_exit",
            RolePreset::Relay => "relay",
            RolePreset::Anchor => "anchor",
            RolePreset::Nas => "nas",
            RolePreset::Llm => "llm",
            RolePreset::BlindRelay => "blind_relay",
        }
    }

    /// Operator-friendly one-line description.
    pub fn description(self) -> &'static str {
        match self {
            RolePreset::Client => "uses the mesh; hosts nothing",
            RolePreset::Admin => {
                "admin workstation: full operational console; no extra mesh duties"
            }
            RolePreset::Exit => "internet egress for other peers (advertises 0.0.0.0/0)",
            RolePreset::BlindExit => {
                "hardened final-hop exit (Linux only; IMMUTABLE — factory reset to change)"
            }
            RolePreset::Relay => "encrypted UDP forwarding for peers that cannot direct-connect",
            RolePreset::Anchor => {
                "always-on home box: gossip seed + relay + bundle-pull + enrollment endpoint"
            }
            RolePreset::Nas => {
                "always-on storage box: tunnel-only backup/restore endpoint, default-deny per signed policy"
            }
            RolePreset::Llm => {
                "always-on AI box: tunnel-only inference API endpoint, default-deny per signed policy"
            }
            RolePreset::BlindRelay => {
                "privacy-preserving unlogged relay hop: identity-blind forwarding, no local \
                 relay identity state (§16 advertisement sign-off pending)"
            }
        }
    }

    /// All presets in canonical order. Wizard surfaces should
    /// present in this order: hosting roles first (anchor, admin,
    /// exit, relay, nas, llm), passive presets last. `blind_relay`
    /// sits with the passive/hardened presets: entering or leaving
    /// it is a privacy-boundary crossing (§6.1), not a routine
    /// capability edit.
    pub fn all() -> &'static [RolePreset; 9] {
        &[
            RolePreset::Anchor,
            RolePreset::Admin,
            RolePreset::Exit,
            RolePreset::Relay,
            RolePreset::Nas,
            RolePreset::Llm,
            RolePreset::Client,
            RolePreset::BlindExit,
            RolePreset::BlindRelay,
        ]
    }
}

impl fmt::Display for RolePreset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RolePreset {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "client" => Ok(RolePreset::Client),
            "admin" => Ok(RolePreset::Admin),
            "exit" => Ok(RolePreset::Exit),
            "blind_exit" | "blind-exit" => Ok(RolePreset::BlindExit),
            "relay" => Ok(RolePreset::Relay),
            "anchor" => Ok(RolePreset::Anchor),
            "nas" => Ok(RolePreset::Nas),
            "llm" => Ok(RolePreset::Llm),
            "blind_relay" | "blind-relay" => Ok(RolePreset::BlindRelay),
            other => Err(format!(
                "invalid role preset: {other:?} (expected one of: anchor, admin, exit, relay, nas, llm, client, blind_exit, blind_relay)"
            )),
        }
    }
}

/// Primary local role (Axis 1).
///
/// Mirrors `crates/rustynetd/src/daemon.rs::NodeRole`. Kept in sync
/// deliberately — `rustynet-control` does not depend on `rustynetd`
/// so the parallel enum is the integration seam. Any addition here
/// must be mirrored in the daemon definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrimaryRole {
    Client,
    Admin,
    BlindExit,
    BlindRelay,
}

impl PrimaryRole {
    pub fn as_str(self) -> &'static str {
        match self {
            PrimaryRole::Client => "client",
            PrimaryRole::Admin => "admin",
            PrimaryRole::BlindExit => "blind_exit",
            PrimaryRole::BlindRelay => "blind_relay",
        }
    }
}

impl fmt::Display for PrimaryRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PrimaryRole {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "client" => Ok(PrimaryRole::Client),
            "admin" => Ok(PrimaryRole::Admin),
            "blind_exit" | "blind-exit" => Ok(PrimaryRole::BlindExit),
            "blind_relay" | "blind-relay" => Ok(PrimaryRole::BlindRelay),
            other => Err(format!(
                "invalid primary role: {other:?} (expected client, admin, blind_exit, or blind_relay)"
            )),
        }
    }
}

/// Composable mesh capability (Axis 2). Signed into the membership
/// bundle alongside node identity.
///
/// Capabilities never gate signature verification. Every consumer
/// independently verifies the signed bundle; capabilities are
/// operational metadata, not trust authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Capability {
    /// Daemon applies forwarding + NAT for `0.0.0.0/0`. Other peers
    /// may select this node as their exit (subject to signed
    /// assignment-bundle authorisation).
    ServesExit,
    /// `rustynet-relay` co-deploys as a sibling service on this host.
    ServesRelay,
    /// Priority gossip rebroadcast — anchor flag (see anchor design).
    AnchorGossipSeed,
    /// LAN-loopback bundle-pull endpoint for new-device bootstrap.
    AnchorBundlePull,
    /// LAN-loopback enrollment-token redemption endpoint.
    AnchorEnrollmentEndpoint,
    /// Indicates relay co-deploys on this host. Equivalent to
    /// [`Capability::ServesRelay`] for relay-binary lifecycle purposes;
    /// distinct field for telemetry clarity on anchor deployments.
    AnchorRelayColocation,
    /// Holds the uPnP/PCP/NAT-PMP lease for this LAN. Multi-anchor
    /// coordination uses lex-min node-id.
    AnchorPortMappingAuthoritative,
    /// `rustynet-nas` co-deploys as a sibling service on this host.
    /// The storage/backup API binds to the mesh tunnel address only;
    /// peer access is governed by signed service-access policy
    /// (default-deny). New variants append after this one — the
    /// derived ordering feeds canonical serialisation and must stay
    /// append-only.
    ServesNas,
    /// `rustynet-llm-gateway` co-deploys as a sibling service on
    /// this host. The inference API binds to the mesh tunnel address
    /// only; peer access is governed by signed service-access policy
    /// (default-deny).
    ServesLlm,
    /// Marks the carrying node as a blind relay: the relay hop must
    /// hold exactly {RelayHost, BlindRelay} in the membership bundle
    /// and nothing else (BlindRelayRoleDesign §5.1). DESIGN-ONLY
    /// pending §16 wire-format sign-off: production advertisement of
    /// this capability remains refused downstream (enrollment
    /// admission + membership reduce gates). New variants append
    /// after this one — the derived ordering feeds canonical
    /// serialisation and must stay append-only.
    BlindRelay,
    /// `rustydnsd` co-deploys as a sibling service on this host for
    /// the RustyDNS tandem DNS integration (see
    /// `RustydnsTandemIntegrationDesign_2026-08-27.md`). Mutually
    /// exclusive with the `blind_exit` role (design §3 invariant 10);
    /// grant is operator-signed, never granted by any preset.
    ServesDns,
}

impl Capability {
    /// Stable wire string. Use for membership-bundle serialisation,
    /// IPC, audit logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Capability::ServesExit => "serves_exit",
            Capability::ServesRelay => "serves_relay",
            Capability::AnchorGossipSeed => "anchor.gossip_seed",
            Capability::AnchorBundlePull => "anchor.bundle_pull",
            Capability::AnchorEnrollmentEndpoint => "anchor.enrollment_endpoint",
            Capability::AnchorRelayColocation => "anchor.relay_colocation",
            Capability::AnchorPortMappingAuthoritative => "anchor.port_mapping_authoritative",
            Capability::ServesNas => "serves_nas",
            Capability::ServesLlm => "serves_llm",
            Capability::BlindRelay => "blind_relay",
            Capability::ServesDns => "serves_dns",
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Capability {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "serves_exit" => Ok(Capability::ServesExit),
            "serves_relay" => Ok(Capability::ServesRelay),
            "anchor.gossip_seed" => Ok(Capability::AnchorGossipSeed),
            "anchor.bundle_pull" => Ok(Capability::AnchorBundlePull),
            "anchor.enrollment_endpoint" => Ok(Capability::AnchorEnrollmentEndpoint),
            "anchor.relay_colocation" => Ok(Capability::AnchorRelayColocation),
            "anchor.port_mapping_authoritative" => Ok(Capability::AnchorPortMappingAuthoritative),
            "serves_nas" => Ok(Capability::ServesNas),
            "serves_llm" => Ok(Capability::ServesLlm),
            "blind_relay" | "blind-relay" => Ok(Capability::BlindRelay),
            "serves_dns" => Ok(Capability::ServesDns),
            other => Err(format!("invalid capability: {other:?}")),
        }
    }
}

/// Full composition of a preset: primary role + capability set.
#[derive(Debug, Clone, Copy)]
pub struct RolePresetComposition {
    pub preset: RolePreset,
    pub primary: PrimaryRole,
    pub capabilities: &'static [Capability],
}

/// Authoritative preset → composition table.
///
/// **Adding a preset requires:** (1) a new [`RolePreset`] variant;
/// (2) a new entry in this table; (3) new transition rows/columns
/// in [`validate_transition`]; (4) wizard + CLI surface updates;
/// (5) per-platform eligibility entries in `PlatformSupportMatrix`.
pub const ROLE_PRESET_TABLE: [RolePresetComposition; 9] = [
    RolePresetComposition {
        preset: RolePreset::Client,
        primary: PrimaryRole::Client,
        capabilities: &[],
    },
    RolePresetComposition {
        preset: RolePreset::Admin,
        primary: PrimaryRole::Admin,
        capabilities: &[],
    },
    RolePresetComposition {
        preset: RolePreset::Exit,
        primary: PrimaryRole::Admin,
        capabilities: &[Capability::ServesExit],
    },
    RolePresetComposition {
        preset: RolePreset::BlindExit,
        primary: PrimaryRole::BlindExit,
        capabilities: &[Capability::ServesExit],
    },
    RolePresetComposition {
        preset: RolePreset::Relay,
        primary: PrimaryRole::Admin,
        capabilities: &[Capability::ServesRelay],
    },
    RolePresetComposition {
        preset: RolePreset::Anchor,
        primary: PrimaryRole::Admin,
        capabilities: &[
            Capability::AnchorGossipSeed,
            Capability::AnchorBundlePull,
            Capability::AnchorEnrollmentEndpoint,
            Capability::AnchorRelayColocation,
            Capability::AnchorPortMappingAuthoritative,
        ],
    },
    RolePresetComposition {
        preset: RolePreset::Nas,
        primary: PrimaryRole::Admin,
        capabilities: &[Capability::ServesNas],
    },
    RolePresetComposition {
        preset: RolePreset::Llm,
        primary: PrimaryRole::Admin,
        capabilities: &[Capability::ServesLlm],
    },
    RolePresetComposition {
        preset: RolePreset::BlindRelay,
        primary: PrimaryRole::BlindRelay,
        // BlindRelayRoleDesign §4.2: the blind relay carries exactly
        // {ServesRelay, BlindRelay} — the relay binary it forwards
        // for, plus the privacy marker. Membership projection is the
        // exact set {RelayHost, BlindRelay} (§5.1) and the reducer
        // rejects any other co-location.
        capabilities: &[Capability::ServesRelay, Capability::BlindRelay],
    },
];

/// Look up the composition for a preset. Always succeeds — every
/// preset variant is in the table.
pub fn composition_for(preset: RolePreset) -> &'static RolePresetComposition {
    ROLE_PRESET_TABLE
        .iter()
        .find(|entry| entry.preset == preset)
        .expect(
            "ROLE_PRESET_TABLE missing entry for a RolePreset variant — \
             this is a build-time invariant violation; adding a preset \
             requires updating the table",
        )
}

/// Whether a capability set requires the `rustynet-relay` binary
/// to be deployed as a sibling service. True if either
/// [`Capability::ServesRelay`] or [`Capability::AnchorRelayColocation`]
/// is present (they are equivalent at the binary lifecycle level).
pub fn capabilities_require_relay_binary(capabilities: &[Capability]) -> bool {
    capabilities.iter().any(|c| {
        matches!(
            c,
            Capability::ServesRelay | Capability::AnchorRelayColocation
        )
    })
}

/// Whether a capability set requires the `rustynet-nas` binary to be
/// deployed as a sibling service.
pub fn capabilities_require_nas_binary(capabilities: &[Capability]) -> bool {
    capabilities
        .iter()
        .any(|c| matches!(c, Capability::ServesNas))
}

/// Whether a capability set requires the `rustynet-llm-gateway`
/// binary to be deployed as a sibling service.
pub fn capabilities_require_llm_binary(capabilities: &[Capability]) -> bool {
    capabilities
        .iter()
        .any(|c| matches!(c, Capability::ServesLlm))
}

/// Whether a capability set requires the `rustydnsd` binary to be
/// deployed as a sibling service (RustyDNS tandem integration).
pub fn capabilities_require_dns_binary(capabilities: &[Capability]) -> bool {
    capabilities
        .iter()
        .any(|c| matches!(c, Capability::ServesDns))
}

/// Sibling service binaries that co-deploy with capability-bearing
/// presets. Each kind has an **independent** deploy/undeploy
/// lifecycle: a single transition can undeploy one service and
/// deploy another (e.g. `nas` → `relay` undeploys `rustynet-nas`
/// and deploys `rustynet-relay`; they share nothing). Contrast
/// `relay` → `anchor`, which is a lifecycle no-op only because both
/// presets keep the same relay binary running.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ServiceKind {
    Relay,
    Nas,
    Llm,
    Dns,
}

impl ServiceKind {
    /// Stable wire string. Use for IPC, CLI args, audit logs.
    pub fn as_str(self) -> &'static str {
        match self {
            ServiceKind::Relay => "relay",
            ServiceKind::Nas => "nas",
            ServiceKind::Llm => "llm",
            ServiceKind::Dns => "dns",
        }
    }

    /// Name of the sibling service binary / crate.
    pub fn binary_name(self) -> &'static str {
        match self {
            ServiceKind::Relay => "rustynet-relay",
            ServiceKind::Nas => "rustynet-nas",
            ServiceKind::Llm => "rustynet-llm-gateway",
            ServiceKind::Dns => "rustydnsd",
        }
    }

    /// All service kinds in canonical (derived `Ord`) order.
    pub fn all() -> &'static [ServiceKind; 4] {
        &[
            ServiceKind::Relay,
            ServiceKind::Nas,
            ServiceKind::Llm,
            ServiceKind::Dns,
        ]
    }

    /// Whether the given capability set requires this service binary
    /// to run as a sibling service.
    pub fn required_by(self, capabilities: &[Capability]) -> bool {
        match self {
            ServiceKind::Relay => capabilities_require_relay_binary(capabilities),
            ServiceKind::Nas => capabilities_require_nas_binary(capabilities),
            ServiceKind::Llm => capabilities_require_llm_binary(capabilities),
            ServiceKind::Dns => capabilities_require_dns_binary(capabilities),
        }
    }
}

impl fmt::Display for ServiceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// All sibling service binaries a capability set requires, in
/// canonical order.
pub fn required_service_binaries(capabilities: &[Capability]) -> Vec<ServiceKind> {
    ServiceKind::all()
        .iter()
        .copied()
        .filter(|kind| kind.required_by(capabilities))
        .collect()
}

/// Top-level transition outcome. Lightweight return type for
/// [`validate_transition`]; for full side-effect details use
/// [`transition_plan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionKind {
    /// `from == to`. No-op.
    Identity,
    /// Primary local role changes (admin ↔ client); no capability
    /// changes. Daemon updates local config + reloads. No signed
    /// bundle required.
    LocalOnly,
    /// Capability set changes. An unsigned `MembershipUpdateRecord`
    /// is emitted; the operator signs and applies it through the
    /// existing membership-update path. Local-only state changes
    /// (e.g. simultaneous primary change) ride along.
    SignedMembership,
    /// Transition is not allowed. The string carries a short
    /// operator-readable reason.
    Blocked(&'static str),
    /// Transition is destructive and one-way. Requires explicit
    /// factory-reset acknowledgement from the operator. The string
    /// carries a short reason for the wizard prompt.
    Irreversible(&'static str),
}

impl TransitionKind {
    pub fn is_allowed(&self) -> bool {
        matches!(
            self,
            TransitionKind::Identity
                | TransitionKind::LocalOnly
                | TransitionKind::SignedMembership
                | TransitionKind::Irreversible(_)
        )
    }

    pub fn requires_owner_signature(&self) -> bool {
        matches!(
            self,
            TransitionKind::SignedMembership | TransitionKind::Irreversible(_)
        )
    }
}

/// Full transition plan. Side-effects the role-transition
/// orchestrator must execute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionPlan {
    pub from: RolePreset,
    pub to: RolePreset,
    pub kind: TransitionKind,
    /// Primary role change, if any. `None` if from and to share
    /// the same primary.
    pub primary_change: Option<(PrimaryRole, PrimaryRole)>,
    /// Capabilities present in the destination but not the source.
    /// Sorted for stable ordering.
    pub adds_capabilities: Vec<Capability>,
    /// Capabilities present in the source but not the destination.
    /// Sorted for stable ordering.
    pub removes_capabilities: Vec<Capability>,
    /// Sibling services the transition must deploy (and verify
    /// healthy) **before** the signed bundle advertises the new
    /// capabilities (deploy-before-advertise). Canonical order.
    pub service_deploys: Vec<ServiceKind>,
    /// Sibling services the transition must undeploy **after**
    /// in-flight sessions are severed and **before** the signed
    /// revocation drops the capability from local state
    /// (teardown/undeploy-before-revoke). Canonical order.
    pub service_undeploys: Vec<ServiceKind>,
    /// True when the transition crosses the blind-relay privacy
    /// boundary (source or destination is `blind_relay`). Phase 2
    /// records the requirement only; the ordered
    /// teardown → purge → residue-verify ceremony itself is the
    /// phase-4 deliverable (BlindRelayRoleDesign §6.1) and MUST be
    /// performed before this plan is executed by the transition
    /// orchestrator. Blocked plans never set this flag — they
    /// compute no side effects at all.
    pub requires_privacy_boundary_reinit: bool,
}

impl TransitionPlan {
    /// Whether this transition deploys the given sibling service.
    pub fn requires_service_deploy(&self, kind: ServiceKind) -> bool {
        self.service_deploys.contains(&kind)
    }

    /// Whether this transition undeploys the given sibling service.
    pub fn requires_service_undeploy(&self, kind: ServiceKind) -> bool {
        self.service_undeploys.contains(&kind)
    }

    /// Whether the transition enters `blind_relay` from a compatible
    /// source. Per BlindRelayRoleDesign §5.1 the blind relay cannot
    /// co-exist with client/entry/exit/anchor identity-bearing state;
    /// only privacy-clean sources (admin, plain relay) may enter.
    pub fn is_blind_relay_entry_compatible(from: RolePreset) -> bool {
        matches!(from, RolePreset::Admin | RolePreset::Relay)
    }
}

/// Validate whether the transition `from → to` is allowed and
/// return the lightweight outcome category.
///
/// Use [`transition_plan`] when the caller also needs the
/// concrete side-effects (capability deltas, relay deploy/undeploy
/// flags).
pub fn validate_transition(from: RolePreset, to: RolePreset) -> TransitionKind {
    transition_plan(from, to).kind
}

/// Compute the full transition plan with side-effects.
pub fn transition_plan(from: RolePreset, to: RolePreset) -> TransitionPlan {
    let from_comp = composition_for(from);
    let to_comp = composition_for(to);

    // Identity: from == to. No side-effects.
    if from == to {
        return TransitionPlan {
            from,
            to,
            kind: TransitionKind::Identity,
            primary_change: None,
            adds_capabilities: Vec::new(),
            removes_capabilities: Vec::new(),
            service_deploys: Vec::new(),
            service_undeploys: Vec::new(),
            requires_privacy_boundary_reinit: false,
        };
    }

    // BlindExit lock-out: leaving BlindExit requires factory reset
    // (key wipe + fresh enrollment), not a role transition.
    if from == RolePreset::BlindExit {
        return TransitionPlan {
            from,
            to,
            kind: TransitionKind::Blocked(
                "blind_exit is immutable; factory reset + fresh key provisioning required to change role",
            ),
            primary_change: None,
            adds_capabilities: Vec::new(),
            removes_capabilities: Vec::new(),
            service_deploys: Vec::new(),
            service_undeploys: Vec::new(),
            requires_privacy_boundary_reinit: false,
        };
    }

    // Blind-relay exclusivity (BlindRelayRoleDesign §5.1): entering
    // blind_relay is only possible from a privacy-clean source. A
    // node carrying client/entry/exit/anchor/application-service
    // state cannot become a blind relay by a role edit — it must
    // first step down to admin (or plain relay), which is its own
    // signed transition. Fail closed: refuse rather than compute a
    // plan that would violate the co-location invariant.
    if to == RolePreset::BlindRelay && !TransitionPlan::is_blind_relay_entry_compatible(from) {
        return TransitionPlan {
            from,
            to,
            kind: TransitionKind::Blocked(
                "blind_relay must be the node's only mesh duty: step down to admin or relay before entering blind_relay (no client/exit/anchor/service co-location, §5.1)",
            ),
            primary_change: None,
            adds_capabilities: Vec::new(),
            removes_capabilities: Vec::new(),
            service_deploys: Vec::new(),
            service_undeploys: Vec::new(),
            requires_privacy_boundary_reinit: false,
        };
    }

    // Compute capability deltas.
    let from_caps: BTreeSet<Capability> = from_comp.capabilities.iter().copied().collect();
    let to_caps: BTreeSet<Capability> = to_comp.capabilities.iter().copied().collect();
    let adds: Vec<Capability> = to_caps.difference(&from_caps).copied().collect();
    let removes: Vec<Capability> = from_caps.difference(&to_caps).copied().collect();

    // Per-service lifecycle deltas. Each service kind is independent:
    // one transition can undeploy one sibling and deploy another
    // (e.g. nas → relay).
    let mut service_deploys = Vec::new();
    let mut service_undeploys = Vec::new();
    for &kind in ServiceKind::all() {
        let from_needs = kind.required_by(from_comp.capabilities);
        let to_needs = kind.required_by(to_comp.capabilities);
        if !from_needs && to_needs {
            service_deploys.push(kind);
        }
        if from_needs && !to_needs {
            service_undeploys.push(kind);
        }
    }

    let primary_change = if from_comp.primary != to_comp.primary {
        Some((from_comp.primary, to_comp.primary))
    } else {
        None
    };

    // Privacy-boundary marker (BlindRelayRoleDesign §6.1): any
    // allowed transition touching blind_relay — entering OR leaving
    // — requires the ordered privacy-boundary reinit ceremony
    // (owner-signed change, typed disclosure acknowledgement, fresh
    // privacy epoch, ordered teardown/deploy + residue verification,
    // audit event). Phase 2 records the requirement; the ceremony is
    // phase 4 and is deliberately NOT performed here.
    let crosses_privacy_boundary = from == RolePreset::BlindRelay || to == RolePreset::BlindRelay;

    // Becoming BlindExit is destructive: wipes existing identity
    // and re-enrolls fresh. Allowed but irreversible — the wizard
    // must confirm with typed acknowledgement. (blind_relay →
    // blind_exit keeps this classification: the target role change
    // is irreversible even though leaving blind_relay itself is
    // reversible via the §6.1 ceremony.)
    let kind = if to == RolePreset::BlindExit {
        TransitionKind::Irreversible(
            "becoming blind_exit wipes node identity and re-enrolls fresh; this cannot be undone without another factory reset",
        )
    } else if !adds.is_empty() || !removes.is_empty() {
        // Capability set changed. Always requires a signed
        // membership update record.
        TransitionKind::SignedMembership
    } else if primary_change.is_some() {
        // Capabilities identical, only primary role differs.
        // Local-only config change (admin ↔ client today).
        TransitionKind::LocalOnly
    } else {
        // No primary change, no capability change. Should be
        // unreachable because we already handled from == to.
        TransitionKind::Identity
    };

    TransitionPlan {
        from,
        to,
        kind,
        primary_change,
        adds_capabilities: adds,
        removes_capabilities: removes,
        service_deploys,
        service_undeploys,
        requires_privacy_boundary_reinit: crosses_privacy_boundary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- Preset table integrity -----

    #[test]
    fn preset_table_has_exactly_nine_entries() {
        assert_eq!(ROLE_PRESET_TABLE.len(), 9);
    }

    #[test]
    fn preset_table_covers_every_role_preset_variant() {
        let presets: BTreeSet<RolePreset> = ROLE_PRESET_TABLE.iter().map(|e| e.preset).collect();
        let expected: BTreeSet<RolePreset> = [
            RolePreset::Client,
            RolePreset::Admin,
            RolePreset::Exit,
            RolePreset::BlindExit,
            RolePreset::Relay,
            RolePreset::Anchor,
            RolePreset::Nas,
            RolePreset::Llm,
            RolePreset::BlindRelay,
        ]
        .iter()
        .copied()
        .collect();
        assert_eq!(presets, expected);
    }

    #[test]
    fn preset_table_no_duplicate_presets() {
        let presets: Vec<RolePreset> = ROLE_PRESET_TABLE.iter().map(|e| e.preset).collect();
        let mut sorted = presets.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(presets.len(), sorted.len());
    }

    #[test]
    fn composition_lookup_round_trip() {
        for entry in ROLE_PRESET_TABLE.iter() {
            let looked_up = composition_for(entry.preset);
            assert_eq!(looked_up.preset, entry.preset);
            assert_eq!(looked_up.primary, entry.primary);
            assert_eq!(looked_up.capabilities, entry.capabilities);
        }
    }

    // ----- Per-preset composition correctness (pinned to taxonomy doc §3.3) -----

    #[test]
    fn client_composition() {
        let comp = composition_for(RolePreset::Client);
        assert_eq!(comp.primary, PrimaryRole::Client);
        assert!(comp.capabilities.is_empty());
    }

    #[test]
    fn admin_composition() {
        let comp = composition_for(RolePreset::Admin);
        assert_eq!(comp.primary, PrimaryRole::Admin);
        assert!(comp.capabilities.is_empty());
    }

    #[test]
    fn exit_composition() {
        let comp = composition_for(RolePreset::Exit);
        assert_eq!(comp.primary, PrimaryRole::Admin);
        assert_eq!(comp.capabilities, &[Capability::ServesExit]);
    }

    #[test]
    fn blind_exit_composition() {
        let comp = composition_for(RolePreset::BlindExit);
        assert_eq!(comp.primary, PrimaryRole::BlindExit);
        assert_eq!(comp.capabilities, &[Capability::ServesExit]);
    }

    #[test]
    fn relay_composition() {
        let comp = composition_for(RolePreset::Relay);
        assert_eq!(comp.primary, PrimaryRole::Admin);
        assert_eq!(comp.capabilities, &[Capability::ServesRelay]);
    }

    #[test]
    fn anchor_composition() {
        let comp = composition_for(RolePreset::Anchor);
        assert_eq!(comp.primary, PrimaryRole::Admin);
        assert_eq!(
            comp.capabilities,
            &[
                Capability::AnchorGossipSeed,
                Capability::AnchorBundlePull,
                Capability::AnchorEnrollmentEndpoint,
                Capability::AnchorRelayColocation,
                Capability::AnchorPortMappingAuthoritative,
            ]
        );
    }

    #[test]
    fn nas_composition() {
        let comp = composition_for(RolePreset::Nas);
        assert_eq!(comp.primary, PrimaryRole::Admin);
        assert_eq!(comp.capabilities, &[Capability::ServesNas]);
    }

    #[test]
    fn llm_composition() {
        let comp = composition_for(RolePreset::Llm);
        assert_eq!(comp.primary, PrimaryRole::Admin);
        assert_eq!(comp.capabilities, &[Capability::ServesLlm]);
    }

    #[test]
    fn blind_relay_composition() {
        // BlindRelayRoleDesign §4.2: dedicated primary role, exactly
        // {ServesRelay, BlindRelay} — never Admin-with-a-checkbox.
        let comp = composition_for(RolePreset::BlindRelay);
        assert_eq!(comp.primary, PrimaryRole::BlindRelay);
        assert_eq!(
            comp.capabilities,
            &[Capability::ServesRelay, Capability::BlindRelay]
        );
    }

    // ----- Str round-trips -----

    #[test]
    fn role_preset_str_round_trip() {
        for &preset in [
            RolePreset::Client,
            RolePreset::Admin,
            RolePreset::Exit,
            RolePreset::BlindExit,
            RolePreset::Relay,
            RolePreset::Anchor,
            RolePreset::Nas,
            RolePreset::Llm,
            RolePreset::BlindRelay,
        ]
        .iter()
        {
            let s = preset.as_str();
            let parsed: RolePreset = s.parse().expect("round trip");
            assert_eq!(parsed, preset);
        }
    }

    #[test]
    fn role_preset_accepts_hyphen_variant_for_blind_exit() {
        assert_eq!(
            "blind-exit".parse::<RolePreset>().unwrap(),
            RolePreset::BlindExit
        );
        assert_eq!(
            "blind_exit".parse::<RolePreset>().unwrap(),
            RolePreset::BlindExit
        );
    }

    #[test]
    fn role_preset_accepts_hyphen_variant_for_blind_relay() {
        // Same alias convention as blind_exit: both spellings parse,
        // and the canonical render is the underscore form.
        assert_eq!(
            "blind-relay".parse::<RolePreset>().unwrap(),
            RolePreset::BlindRelay
        );
        assert_eq!(
            "blind_relay".parse::<RolePreset>().unwrap(),
            RolePreset::BlindRelay
        );
        assert_eq!(RolePreset::BlindRelay.as_str(), "blind_relay");
        assert_eq!(RolePreset::BlindRelay.to_string(), "blind_relay");
    }

    #[test]
    fn role_preset_rejects_unknown() {
        assert!("supernode".parse::<RolePreset>().is_err());
        assert!("".parse::<RolePreset>().is_err());
        assert!("hub".parse::<RolePreset>().is_err());
    }

    #[test]
    fn primary_role_str_round_trip() {
        for &primary in [
            PrimaryRole::Client,
            PrimaryRole::Admin,
            PrimaryRole::BlindExit,
            PrimaryRole::BlindRelay,
        ]
        .iter()
        {
            let s = primary.as_str();
            let parsed: PrimaryRole = s.parse().expect("round trip");
            assert_eq!(parsed, primary);
        }
    }

    #[test]
    fn primary_role_blind_relay_accepts_hyphen_alias() {
        assert_eq!(
            "blind-relay".parse::<PrimaryRole>().unwrap(),
            PrimaryRole::BlindRelay
        );
        assert_eq!(PrimaryRole::BlindRelay.as_str(), "blind_relay");
    }

    #[test]
    fn capability_str_round_trip() {
        for &cap in [
            Capability::ServesExit,
            Capability::ServesRelay,
            Capability::AnchorGossipSeed,
            Capability::AnchorBundlePull,
            Capability::AnchorEnrollmentEndpoint,
            Capability::AnchorRelayColocation,
            Capability::AnchorPortMappingAuthoritative,
            Capability::ServesNas,
            Capability::ServesLlm,
            Capability::BlindRelay,
        ]
        .iter()
        {
            let s = cap.as_str();
            let parsed: Capability = s.parse().expect("round trip");
            assert_eq!(parsed, cap);
        }
    }

    #[test]
    fn capability_blind_relay_accepts_hyphen_alias() {
        assert_eq!(
            "blind-relay".parse::<Capability>().unwrap(),
            Capability::BlindRelay
        );
        assert_eq!(Capability::BlindRelay.as_str(), "blind_relay");
    }

    #[test]
    fn capability_rejects_unknown() {
        assert!("super_cap".parse::<Capability>().is_err());
        assert!("anchor.bogus".parse::<Capability>().is_err());
        assert!("serves_storage".parse::<Capability>().is_err());
    }

    #[test]
    fn capability_ordering_is_append_only() {
        // Canonical serialisation (BTreeSet deltas, signed
        // pre-images) relies on the derived ordering. New variants
        // append after the existing ones; this pin fails if anyone
        // reorders the enum.
        assert!(Capability::AnchorPortMappingAuthoritative < Capability::ServesNas);
        assert!(Capability::ServesNas < Capability::ServesLlm);
        // BlindRelay appended last (phase 2) — ordering must stay
        // append-only for canonical serialisation.
        assert!(Capability::ServesLlm < Capability::BlindRelay);
    }

    // ----- Relay-binary requirement -----

    #[test]
    fn relay_binary_required_when_serves_relay() {
        assert!(capabilities_require_relay_binary(&[
            Capability::ServesRelay
        ]));
    }

    #[test]
    fn relay_binary_required_when_anchor_relay_colocation() {
        assert!(capabilities_require_relay_binary(&[
            Capability::AnchorRelayColocation
        ]));
    }

    #[test]
    fn relay_binary_required_when_both_flags() {
        assert!(capabilities_require_relay_binary(&[
            Capability::ServesRelay,
            Capability::AnchorRelayColocation,
        ]));
    }

    #[test]
    fn relay_binary_not_required_for_empty() {
        assert!(!capabilities_require_relay_binary(&[]));
    }

    #[test]
    fn relay_binary_not_required_for_exit_only() {
        assert!(!capabilities_require_relay_binary(&[
            Capability::ServesExit
        ]));
    }

    #[test]
    fn relay_binary_not_required_for_anchor_non_relay_caps() {
        assert!(!capabilities_require_relay_binary(&[
            Capability::AnchorGossipSeed,
            Capability::AnchorBundlePull,
        ]));
    }

    #[test]
    fn relay_binary_not_required_for_service_hosting_caps() {
        assert!(!capabilities_require_relay_binary(&[
            Capability::ServesNas,
            Capability::ServesLlm,
        ]));
    }

    // ----- NAS / LLM binary requirements -----

    #[test]
    fn nas_binary_required_when_serves_nas() {
        assert!(capabilities_require_nas_binary(&[Capability::ServesNas]));
    }

    #[test]
    fn nas_binary_not_required_for_empty_or_other_caps() {
        assert!(!capabilities_require_nas_binary(&[]));
        assert!(!capabilities_require_nas_binary(&[
            Capability::ServesExit,
            Capability::ServesRelay,
            Capability::ServesLlm,
        ]));
    }

    #[test]
    fn llm_binary_required_when_serves_llm() {
        assert!(capabilities_require_llm_binary(&[Capability::ServesLlm]));
    }

    #[test]
    fn llm_binary_not_required_for_empty_or_other_caps() {
        assert!(!capabilities_require_llm_binary(&[]));
        assert!(!capabilities_require_llm_binary(&[
            Capability::ServesExit,
            Capability::ServesRelay,
            Capability::ServesNas,
        ]));
    }

    // ----- ServiceKind -----

    #[test]
    fn service_kind_str_and_binary_names() {
        assert_eq!(ServiceKind::Relay.as_str(), "relay");
        assert_eq!(ServiceKind::Nas.as_str(), "nas");
        assert_eq!(ServiceKind::Llm.as_str(), "llm");
        assert_eq!(ServiceKind::Dns.as_str(), "dns");
        assert_eq!(ServiceKind::Relay.binary_name(), "rustynet-relay");
        assert_eq!(ServiceKind::Nas.binary_name(), "rustynet-nas");
        assert_eq!(ServiceKind::Llm.binary_name(), "rustynet-llm-gateway");
        assert_eq!(ServiceKind::Dns.binary_name(), "rustydnsd");
    }

    #[test]
    fn service_kind_all_covers_every_variant_in_canonical_order() {
        assert_eq!(
            ServiceKind::all(),
            &[
                ServiceKind::Relay,
                ServiceKind::Nas,
                ServiceKind::Llm,
                ServiceKind::Dns
            ]
        );
    }

    #[test]
    fn serves_dns_capability_round_trips_and_no_preset_grants_it() {
        assert_eq!(Capability::ServesDns.as_str(), "serves_dns");
        assert_eq!(
            "serves_dns".parse::<Capability>().unwrap(),
            Capability::ServesDns
        );
        // Tandem DNS is a signed operator toggle, never a preset
        // capability: no entry in ROLE_PRESET_TABLE grants it.
        for entry in ROLE_PRESET_TABLE {
            assert!(
                !entry.capabilities.contains(&Capability::ServesDns),
                "preset {:?} must not grant ServesDns",
                entry.preset
            );
        }
        assert!(capabilities_require_dns_binary(&[Capability::ServesDns]));
        assert!(!capabilities_require_dns_binary(&[
            Capability::ServesRelay,
            Capability::ServesNas,
            Capability::ServesLlm
        ]));
        assert_eq!(
            required_service_binaries(&[Capability::ServesDns]),
            vec![ServiceKind::Dns]
        );
    }

    #[test]
    fn required_service_binaries_empty_for_no_capabilities() {
        assert!(required_service_binaries(&[]).is_empty());
    }

    #[test]
    fn required_service_binaries_per_preset() {
        assert!(
            required_service_binaries(composition_for(RolePreset::Client).capabilities).is_empty()
        );
        assert!(
            required_service_binaries(composition_for(RolePreset::Admin).capabilities).is_empty()
        );
        assert!(
            required_service_binaries(composition_for(RolePreset::Exit).capabilities).is_empty()
        );
        assert_eq!(
            required_service_binaries(composition_for(RolePreset::Relay).capabilities),
            vec![ServiceKind::Relay]
        );
        assert_eq!(
            required_service_binaries(composition_for(RolePreset::Anchor).capabilities),
            vec![ServiceKind::Relay]
        );
        assert_eq!(
            required_service_binaries(composition_for(RolePreset::Nas).capabilities),
            vec![ServiceKind::Nas]
        );
        assert_eq!(
            required_service_binaries(composition_for(RolePreset::Llm).capabilities),
            vec![ServiceKind::Llm]
        );
        // blind_relay keeps the relay binary running (it forwards via
        // rustynet-relay) — nothing else to deploy.
        assert_eq!(
            required_service_binaries(composition_for(RolePreset::BlindRelay).capabilities),
            vec![ServiceKind::Relay]
        );
    }

    // ----- Identity transitions -----

    #[test]
    fn identity_transition_for_every_preset() {
        for entry in ROLE_PRESET_TABLE.iter() {
            let plan = transition_plan(entry.preset, entry.preset);
            assert_eq!(plan.kind, TransitionKind::Identity);
            assert!(plan.adds_capabilities.is_empty());
            assert!(plan.removes_capabilities.is_empty());
            assert!(plan.primary_change.is_none());
            assert!(plan.service_deploys.is_empty());
            assert!(plan.service_undeploys.is_empty());
        }
    }

    // ----- Blocked transitions (from BlindExit) -----

    #[test]
    fn every_transition_leaving_blind_exit_is_blocked() {
        // Irreversibility: blind_exit has no exit transition. Any
        // target role must come back TransitionKind::Blocked and be
        // disallowed.
        for &to in [
            RolePreset::Client,
            RolePreset::Admin,
            RolePreset::Exit,
            RolePreset::Relay,
            RolePreset::Anchor,
            RolePreset::Nas,
            RolePreset::Llm,
            RolePreset::BlindRelay,
        ]
        .iter()
        {
            let kind = validate_transition(RolePreset::BlindExit, to);
            assert!(
                matches!(kind, TransitionKind::Blocked(_)),
                "blind_exit → {to:?} must be Blocked, got {kind:?}"
            );
            assert!(
                !kind.is_allowed(),
                "blind_exit → {to:?} must not be allowed"
            );
        }
    }

    #[test]
    fn blind_exit_to_anything_else_is_blocked() {
        for &to in [
            RolePreset::Client,
            RolePreset::Admin,
            RolePreset::Exit,
            RolePreset::Relay,
            RolePreset::Anchor,
            RolePreset::Nas,
            RolePreset::Llm,
            RolePreset::BlindRelay,
        ]
        .iter()
        {
            let kind = validate_transition(RolePreset::BlindExit, to);
            assert!(
                matches!(kind, TransitionKind::Blocked(_)),
                "expected Blocked for blind_exit → {to:?}, got {kind:?}"
            );
            assert!(!kind.is_allowed());
        }
    }

    #[test]
    fn blind_exit_to_blind_exit_is_identity() {
        assert_eq!(
            validate_transition(RolePreset::BlindExit, RolePreset::BlindExit),
            TransitionKind::Identity,
        );
    }

    #[test]
    fn blind_exit_lockout_pins_reason_and_empty_side_effects() {
        // The existing Blocked sweep only matches `Blocked(_)`. This
        // pins the exact lock-out reason and that a blocked plan
        // carries NO side-effects, so neither the message nor an
        // accidentally-computed delta can drift.
        for &to in [
            RolePreset::Client,
            RolePreset::Admin,
            RolePreset::Exit,
            RolePreset::Relay,
            RolePreset::Anchor,
            RolePreset::Nas,
            RolePreset::Llm,
            RolePreset::BlindRelay,
        ]
        .iter()
        {
            let plan = transition_plan(RolePreset::BlindExit, to);
            assert_eq!(plan.from, RolePreset::BlindExit);
            assert_eq!(plan.to, to);
            match plan.kind {
                TransitionKind::Blocked(reason) => assert_eq!(
                    reason,
                    "blind_exit is immutable; factory reset + fresh key provisioning required to change role",
                ),
                other => panic!("expected Blocked for blind_exit → {to:?}, got {other:?}"),
            }
            assert!(
                plan.primary_change.is_none(),
                "blocked blind_exit → {to:?} must not change primary role"
            );
            assert!(
                plan.adds_capabilities.is_empty() && plan.removes_capabilities.is_empty(),
                "blocked blind_exit → {to:?} must not compute capability deltas"
            );
            assert!(
                plan.service_deploys.is_empty() && plan.service_undeploys.is_empty(),
                "blocked blind_exit → {to:?} must not schedule service lifecycle"
            );
        }
    }

    // ----- Irreversible transitions (into BlindExit) -----

    #[test]
    fn anything_to_blind_exit_is_irreversible() {
        for &from in [
            RolePreset::Client,
            RolePreset::Admin,
            RolePreset::Exit,
            RolePreset::Relay,
            RolePreset::Anchor,
            RolePreset::Nas,
            RolePreset::Llm,
            RolePreset::BlindRelay,
        ]
        .iter()
        {
            let kind = validate_transition(from, RolePreset::BlindExit);
            assert!(
                matches!(kind, TransitionKind::Irreversible(_)),
                "expected Irreversible for {from:?} → blind_exit, got {kind:?}"
            );
            assert!(kind.is_allowed());
            assert!(kind.requires_owner_signature());
        }
    }

    // ----- Local-only transitions (admin ↔ client) -----

    #[test]
    fn client_to_admin_transition_needs_no_owner_signature() {
        // Client → Admin changes ONLY the primary role (identical
        // capability sets), so it is a local-only configuration
        // change: allowed WITHOUT an owner-signed membership record.
        let kind = validate_transition(RolePreset::Client, RolePreset::Admin);
        assert_eq!(kind, TransitionKind::LocalOnly);
        assert!(
            !kind.requires_owner_signature(),
            "client → admin must not require an owner signature"
        );

        // The full plan agrees and carries exactly the primary flip.
        let plan = transition_plan(RolePreset::Client, RolePreset::Admin);
        assert_eq!(plan.kind, TransitionKind::LocalOnly);
        assert_eq!(plan.from, RolePreset::Client);
        assert_eq!(plan.to, RolePreset::Admin);
        assert_eq!(
            plan.primary_change,
            Some((PrimaryRole::Client, PrimaryRole::Admin))
        );
        assert!(plan.adds_capabilities.is_empty());
        assert!(plan.removes_capabilities.is_empty());
    }

    #[test]
    fn same_role_transition_is_identity_no_op() {
        // A transition whose from equals its to is a no-op: Identity,
        // allowed, and requiring no owner signature. BlindExit is
        // included deliberately — its lock-out arm must sit AFTER the
        // identity short-circuit, or a no-op would read as Blocked.
        for &preset in [
            RolePreset::Client,
            RolePreset::Admin,
            RolePreset::Exit,
            RolePreset::Relay,
            RolePreset::Anchor,
            RolePreset::Nas,
            RolePreset::Llm,
            RolePreset::BlindExit,
            RolePreset::BlindRelay,
        ]
        .iter()
        {
            let kind = validate_transition(preset, preset);
            assert_eq!(kind, TransitionKind::Identity, "{preset:?} → itself");
            assert!(kind.is_allowed(), "{preset:?} → itself must be allowed");
            assert!(
                !kind.requires_owner_signature(),
                "{preset:?} → itself must not require an owner signature"
            );
        }
    }

    #[test]
    fn becoming_blind_exit_is_irreversible_with_destructive_reason() {
        // Becoming blind_exit wipes node identity and re-enrolls
        // fresh: allowed, but classified Irreversible and requiring
        // an owner signature. The exact destructive reason is pinned
        // so it cannot silently weaken.
        let plan = transition_plan(RolePreset::Admin, RolePreset::BlindExit);
        assert_eq!(plan.from, RolePreset::Admin);
        assert_eq!(plan.to, RolePreset::BlindExit);
        match plan.kind {
            TransitionKind::Irreversible(reason) => assert_eq!(
                reason,
                "becoming blind_exit wipes node identity and re-enrolls fresh; this cannot be undone without another factory reset",
            ),
            other => panic!("expected Irreversible, got {other:?}"),
        }
        assert!(plan.kind.is_allowed());
        assert!(plan.kind.requires_owner_signature());

        let kind = validate_transition(RolePreset::Admin, RolePreset::BlindExit);
        assert!(matches!(kind, TransitionKind::Irreversible(_)));
    }

    #[test]
    fn leaving_blind_exit_for_llm_is_blocked() {
        // Immutable lock-out: a transition FROM blind_exit toward any
        // role is Blocked — the node's identity cannot be changed,
        // only wiped by factory reset.
        let kind = validate_transition(RolePreset::BlindExit, RolePreset::Llm);
        assert!(
            matches!(kind, TransitionKind::Blocked(_)),
            "blind_exit → llm must be Blocked, got {kind:?}"
        );
        assert!(!kind.is_allowed());
    }

    #[test]
    fn admin_to_client_is_local_only() {
        let plan = transition_plan(RolePreset::Admin, RolePreset::Client);
        assert_eq!(plan.kind, TransitionKind::LocalOnly);
        assert!(plan.adds_capabilities.is_empty());
        assert!(plan.removes_capabilities.is_empty());
        assert_eq!(
            plan.primary_change,
            Some((PrimaryRole::Admin, PrimaryRole::Client))
        );
        assert!(plan.service_deploys.is_empty());
        assert!(plan.service_undeploys.is_empty());
        assert!(!plan.kind.requires_owner_signature());
    }

    #[test]
    fn client_to_admin_is_local_only() {
        let plan = transition_plan(RolePreset::Client, RolePreset::Admin);
        assert_eq!(plan.kind, TransitionKind::LocalOnly);
        assert_eq!(
            plan.primary_change,
            Some((PrimaryRole::Client, PrimaryRole::Admin))
        );
        assert!(!plan.kind.requires_owner_signature());
    }

    // ----- Signed-membership transitions -----

    #[test]
    fn admin_to_exit_is_signed_membership() {
        let plan = transition_plan(RolePreset::Admin, RolePreset::Exit);
        assert_eq!(plan.kind, TransitionKind::SignedMembership);
        assert_eq!(plan.adds_capabilities, vec![Capability::ServesExit]);
        assert!(plan.removes_capabilities.is_empty());
        assert!(plan.primary_change.is_none());
        assert!(plan.service_deploys.is_empty());
        assert!(plan.service_undeploys.is_empty());
        assert!(plan.kind.requires_owner_signature());
    }

    #[test]
    fn exit_to_admin_is_signed_membership() {
        let plan = transition_plan(RolePreset::Exit, RolePreset::Admin);
        assert_eq!(plan.kind, TransitionKind::SignedMembership);
        assert!(plan.adds_capabilities.is_empty());
        assert_eq!(plan.removes_capabilities, vec![Capability::ServesExit]);
    }

    #[test]
    fn admin_to_exit_adding_serves_exit_is_signed_membership() {
        // Adding the serves_exit capability changes the capability
        // set, so the transition MUST be classified SignedMembership
        // and require an owner signature — never a local-only flip.
        let plan = transition_plan(RolePreset::Admin, RolePreset::Exit);
        assert_eq!(plan.adds_capabilities, vec![Capability::ServesExit]);
        assert_eq!(plan.kind, TransitionKind::SignedMembership);
        assert!(
            plan.kind.requires_owner_signature(),
            "adding serves_exit must require an owner signature"
        );

        let kind = validate_transition(RolePreset::Admin, RolePreset::Exit);
        assert_eq!(kind, TransitionKind::SignedMembership);
        assert!(kind.requires_owner_signature());
    }

    #[test]
    fn client_to_exit_is_signed_membership_with_primary_change() {
        let plan = transition_plan(RolePreset::Client, RolePreset::Exit);
        assert_eq!(plan.kind, TransitionKind::SignedMembership);
        assert_eq!(plan.adds_capabilities, vec![Capability::ServesExit]);
        assert_eq!(
            plan.primary_change,
            Some((PrimaryRole::Client, PrimaryRole::Admin))
        );
    }

    // ----- Relay deploy / undeploy -----

    #[test]
    fn adding_serves_relay_requires_owner_signed_membership() {
        // Adding serves_relay changes the capability set: the
        // transition must be SignedMembership AND require an owner
        // signature — a relay cannot be stood up by local config.
        let plan = transition_plan(RolePreset::Admin, RolePreset::Relay);
        assert_eq!(plan.adds_capabilities, vec![Capability::ServesRelay]);
        assert_eq!(plan.kind, TransitionKind::SignedMembership);
        assert!(
            plan.kind.requires_owner_signature(),
            "adding serves_relay must require an owner signature"
        );
        let kind = validate_transition(RolePreset::Admin, RolePreset::Relay);
        assert_eq!(kind, TransitionKind::SignedMembership);
        assert!(kind.requires_owner_signature());
    }

    #[test]
    fn removing_serves_exit_requires_owner_signed_membership() {
        // Removing serves_exit changes the capability set: the
        // transition must be SignedMembership AND require an owner
        // signature — exit capability cannot be silently stripped.
        let plan = transition_plan(RolePreset::Exit, RolePreset::Admin);
        assert_eq!(plan.removes_capabilities, vec![Capability::ServesExit]);
        assert!(plan.adds_capabilities.is_empty());
        assert_eq!(plan.kind, TransitionKind::SignedMembership);
        assert!(
            plan.kind.requires_owner_signature(),
            "removing serves_exit must require an owner signature"
        );
        let kind = validate_transition(RolePreset::Exit, RolePreset::Admin);
        assert_eq!(kind, TransitionKind::SignedMembership);
        assert!(kind.requires_owner_signature());
    }

    #[test]
    fn adding_serves_nas_requires_owner_signed_membership() {
        // Adding serves_nas changes the capability set: the transition
        // must be SignedMembership AND require an owner signature —
        // storage service cannot be enabled by local config.
        let plan = transition_plan(RolePreset::Admin, RolePreset::Nas);
        assert_eq!(plan.adds_capabilities, vec![Capability::ServesNas]);
        assert_eq!(plan.kind, TransitionKind::SignedMembership);
        assert!(
            plan.kind.requires_owner_signature(),
            "adding serves_nas must require an owner signature"
        );
        let kind = validate_transition(RolePreset::Admin, RolePreset::Nas);
        assert_eq!(kind, TransitionKind::SignedMembership);
        assert!(kind.requires_owner_signature());
    }

    #[test]
    fn adding_serves_llm_requires_owner_signed_membership() {
        // Adding serves_llm changes the capability set: the transition
        // must be SignedMembership AND require an owner signature —
        // LLM gateway service cannot be enabled by local config.
        let plan = transition_plan(RolePreset::Admin, RolePreset::Llm);
        assert_eq!(plan.adds_capabilities, vec![Capability::ServesLlm]);
        assert_eq!(plan.kind, TransitionKind::SignedMembership);
        assert!(
            plan.kind.requires_owner_signature(),
            "adding serves_llm must require an owner signature"
        );
        let kind = validate_transition(RolePreset::Admin, RolePreset::Llm);
        assert_eq!(kind, TransitionKind::SignedMembership);
        assert!(kind.requires_owner_signature());
    }

    #[test]
    fn removing_serves_relay_requires_owner_signed_membership() {
        // Removing serves_relay changes the capability set: the
        // transition must be SignedMembership AND require an owner
        // signature — relay service cannot be torn down by local
        // config alone.
        let plan = transition_plan(RolePreset::Relay, RolePreset::Admin);
        assert_eq!(plan.removes_capabilities, vec![Capability::ServesRelay]);
        assert!(plan.adds_capabilities.is_empty());
        assert_eq!(plan.kind, TransitionKind::SignedMembership);
        assert!(
            plan.kind.requires_owner_signature(),
            "removing serves_relay must require an owner signature"
        );
        let kind = validate_transition(RolePreset::Relay, RolePreset::Admin);
        assert_eq!(kind, TransitionKind::SignedMembership);
        assert!(kind.requires_owner_signature());
    }

    #[test]
    fn removing_serves_nas_requires_owner_signed_membership() {
        // Removing serves_nas changes the capability set: the
        // transition must be SignedMembership AND require an owner
        // signature — NAS storage cannot be torn down by local config.
        let plan = transition_plan(RolePreset::Nas, RolePreset::Admin);
        assert_eq!(plan.removes_capabilities, vec![Capability::ServesNas]);
        assert!(plan.adds_capabilities.is_empty());
        assert_eq!(plan.kind, TransitionKind::SignedMembership);
        assert!(
            plan.kind.requires_owner_signature(),
            "removing serves_nas must require an owner signature"
        );
        let kind = validate_transition(RolePreset::Nas, RolePreset::Admin);
        assert_eq!(kind, TransitionKind::SignedMembership);
        assert!(kind.requires_owner_signature());
    }

    #[test]
    fn removing_serves_llm_requires_owner_signed_membership() {
        // Removing serves_llm changes the capability set: the
        // transition must be SignedMembership AND require an owner
        // signature — LLM gateway cannot be torn down by local config.
        let plan = transition_plan(RolePreset::Llm, RolePreset::Admin);
        assert_eq!(plan.removes_capabilities, vec![Capability::ServesLlm]);
        assert!(plan.adds_capabilities.is_empty());
        assert_eq!(plan.kind, TransitionKind::SignedMembership);
        assert!(
            plan.kind.requires_owner_signature(),
            "removing serves_llm must require an owner signature"
        );
        let kind = validate_transition(RolePreset::Llm, RolePreset::Admin);
        assert_eq!(kind, TransitionKind::SignedMembership);
        assert!(kind.requires_owner_signature());
    }

    #[test]
    fn admin_to_relay_requires_deploy() {
        let plan = transition_plan(RolePreset::Admin, RolePreset::Relay);
        assert_eq!(plan.kind, TransitionKind::SignedMembership);
        assert_eq!(plan.adds_capabilities, vec![Capability::ServesRelay]);
        assert_eq!(plan.service_deploys, vec![ServiceKind::Relay]);
        assert!(plan.service_undeploys.is_empty());
        assert!(plan.requires_service_deploy(ServiceKind::Relay));
        assert!(!plan.requires_service_undeploy(ServiceKind::Relay));
    }

    #[test]
    fn relay_to_admin_requires_undeploy() {
        let plan = transition_plan(RolePreset::Relay, RolePreset::Admin);
        assert_eq!(plan.kind, TransitionKind::SignedMembership);
        assert_eq!(plan.removes_capabilities, vec![Capability::ServesRelay]);
        assert!(plan.service_deploys.is_empty());
        assert_eq!(plan.service_undeploys, vec![ServiceKind::Relay]);
    }

    #[test]
    fn admin_to_anchor_requires_deploy() {
        let plan = transition_plan(RolePreset::Admin, RolePreset::Anchor);
        assert_eq!(plan.kind, TransitionKind::SignedMembership);
        assert_eq!(plan.service_deploys, vec![ServiceKind::Relay]);
        assert!(plan.service_undeploys.is_empty());
        // Anchor adds all five anchor.* capabilities.
        assert_eq!(plan.adds_capabilities.len(), 5);
        assert!(
            plan.adds_capabilities
                .contains(&Capability::AnchorRelayColocation)
        );
    }

    #[test]
    fn anchor_to_admin_requires_undeploy() {
        let plan = transition_plan(RolePreset::Anchor, RolePreset::Admin);
        assert_eq!(plan.service_undeploys, vec![ServiceKind::Relay]);
        assert!(plan.service_deploys.is_empty());
        assert_eq!(plan.removes_capabilities.len(), 5);
    }

    #[test]
    fn relay_to_anchor_no_relay_lifecycle_change() {
        let plan = transition_plan(RolePreset::Relay, RolePreset::Anchor);
        assert_eq!(plan.kind, TransitionKind::SignedMembership);
        // Both presets keep the relay binary running. AnchorRelayColocation
        // replaces ServesRelay; from a binary-lifecycle standpoint, no
        // deploy/undeploy is needed.
        assert!(plan.service_deploys.is_empty());
        assert!(plan.service_undeploys.is_empty());
        // ServesRelay is removed, the five anchor.* caps are added.
        assert!(plan.removes_capabilities.contains(&Capability::ServesRelay));
        assert!(
            plan.adds_capabilities
                .contains(&Capability::AnchorRelayColocation)
        );
    }

    #[test]
    fn anchor_to_relay_no_relay_lifecycle_change() {
        let plan = transition_plan(RolePreset::Anchor, RolePreset::Relay);
        assert!(plan.service_deploys.is_empty());
        assert!(plan.service_undeploys.is_empty());
        assert!(plan.adds_capabilities.contains(&Capability::ServesRelay));
        assert!(
            plan.removes_capabilities
                .contains(&Capability::AnchorRelayColocation)
        );
    }

    // ----- NAS / LLM deploy / undeploy (taxonomy extension §4) -----

    #[test]
    fn admin_to_nas_requires_nas_deploy() {
        let plan = transition_plan(RolePreset::Admin, RolePreset::Nas);
        assert_eq!(plan.kind, TransitionKind::SignedMembership);
        assert_eq!(plan.adds_capabilities, vec![Capability::ServesNas]);
        assert!(plan.removes_capabilities.is_empty());
        assert!(plan.primary_change.is_none());
        assert_eq!(plan.service_deploys, vec![ServiceKind::Nas]);
        assert!(plan.service_undeploys.is_empty());
        assert!(plan.kind.requires_owner_signature());
    }

    #[test]
    fn nas_to_admin_requires_nas_undeploy() {
        let plan = transition_plan(RolePreset::Nas, RolePreset::Admin);
        assert_eq!(plan.kind, TransitionKind::SignedMembership);
        assert_eq!(plan.removes_capabilities, vec![Capability::ServesNas]);
        assert!(plan.service_deploys.is_empty());
        assert_eq!(plan.service_undeploys, vec![ServiceKind::Nas]);
    }

    #[test]
    fn admin_to_llm_requires_llm_deploy() {
        let plan = transition_plan(RolePreset::Admin, RolePreset::Llm);
        assert_eq!(plan.kind, TransitionKind::SignedMembership);
        assert_eq!(plan.adds_capabilities, vec![Capability::ServesLlm]);
        assert!(plan.removes_capabilities.is_empty());
        assert!(plan.primary_change.is_none());
        assert_eq!(plan.service_deploys, vec![ServiceKind::Llm]);
        assert!(plan.service_undeploys.is_empty());
        assert!(plan.kind.requires_owner_signature());
    }

    #[test]
    fn llm_to_admin_requires_llm_undeploy() {
        let plan = transition_plan(RolePreset::Llm, RolePreset::Admin);
        assert_eq!(plan.kind, TransitionKind::SignedMembership);
        assert_eq!(plan.removes_capabilities, vec![Capability::ServesLlm]);
        assert!(plan.service_deploys.is_empty());
        assert_eq!(plan.service_undeploys, vec![ServiceKind::Llm]);
    }

    #[test]
    fn client_to_nas_is_signed_membership_with_primary_change_and_deploy() {
        let plan = transition_plan(RolePreset::Client, RolePreset::Nas);
        assert_eq!(plan.kind, TransitionKind::SignedMembership);
        assert_eq!(plan.adds_capabilities, vec![Capability::ServesNas]);
        assert_eq!(
            plan.primary_change,
            Some((PrimaryRole::Client, PrimaryRole::Admin))
        );
        assert_eq!(plan.service_deploys, vec![ServiceKind::Nas]);
    }

    #[test]
    fn relay_to_nas_fires_both_lifecycles() {
        // nas and relay share nothing: a single transition undeploys
        // rustynet-relay and deploys rustynet-nas (taxonomy ext §4
        // "deploy+undeploy" cell — unlike relay↔anchor which share
        // the relay binary).
        let plan = transition_plan(RolePreset::Relay, RolePreset::Nas);
        assert_eq!(plan.kind, TransitionKind::SignedMembership);
        assert_eq!(plan.service_deploys, vec![ServiceKind::Nas]);
        assert_eq!(plan.service_undeploys, vec![ServiceKind::Relay]);
    }

    #[test]
    fn nas_to_relay_fires_both_lifecycles() {
        let plan = transition_plan(RolePreset::Nas, RolePreset::Relay);
        assert_eq!(plan.service_deploys, vec![ServiceKind::Relay]);
        assert_eq!(plan.service_undeploys, vec![ServiceKind::Nas]);
    }

    #[test]
    fn anchor_to_llm_fires_both_lifecycles() {
        let plan = transition_plan(RolePreset::Anchor, RolePreset::Llm);
        assert_eq!(plan.kind, TransitionKind::SignedMembership);
        assert_eq!(plan.service_deploys, vec![ServiceKind::Llm]);
        assert_eq!(plan.service_undeploys, vec![ServiceKind::Relay]);
    }

    #[test]
    fn nas_to_llm_fires_both_lifecycles() {
        let plan = transition_plan(RolePreset::Nas, RolePreset::Llm);
        assert_eq!(plan.kind, TransitionKind::SignedMembership);
        assert_eq!(plan.adds_capabilities, vec![Capability::ServesLlm]);
        assert_eq!(plan.removes_capabilities, vec![Capability::ServesNas]);
        assert_eq!(plan.service_deploys, vec![ServiceKind::Llm]);
        assert_eq!(plan.service_undeploys, vec![ServiceKind::Nas]);
    }

    #[test]
    fn llm_to_nas_fires_both_lifecycles() {
        let plan = transition_plan(RolePreset::Llm, RolePreset::Nas);
        assert_eq!(plan.service_deploys, vec![ServiceKind::Nas]);
        assert_eq!(plan.service_undeploys, vec![ServiceKind::Llm]);
    }

    #[test]
    fn nas_to_client_is_signed_with_undeploy_and_primary_change() {
        let plan = transition_plan(RolePreset::Nas, RolePreset::Client);
        assert_eq!(plan.kind, TransitionKind::SignedMembership);
        assert_eq!(plan.removes_capabilities, vec![Capability::ServesNas]);
        assert_eq!(
            plan.primary_change,
            Some((PrimaryRole::Admin, PrimaryRole::Client))
        );
        assert_eq!(plan.service_undeploys, vec![ServiceKind::Nas]);
        assert!(plan.service_deploys.is_empty());
    }

    // ----- Exhaustive matrix coverage (every from × to cell) -----

    /// Reference transition matrix mirrored from
    /// `documents/operations/active/NodeRoleTaxonomy_2026-05-21.md` §5,
    /// extended to eight presets by
    /// `documents/operations/active/NodeRoleTaxonomyExtension_2026-06-11.md` §4
    /// (`nas`/`llm` behave exactly like `relay`: capability change ⇒
    /// signed; no new blocked/irreversible cells) and to nine by
    /// `documents/operations/active/BlindRelayRoleDesign_2026-08-27.md`
    /// §5.1/§6 (entering `blind_relay` from an incompatible role is
    /// Blocked; leaving it is signed; `→ blind_exit` stays
    /// Irreversible). Drift between this table and
    /// `validate_transition` is a test failure and a docs-vs-code
    /// synchronisation defect.
    fn expected_kind(from: RolePreset, to: RolePreset) -> TransitionKind {
        use RolePreset::*;
        match (from, to) {
            (a, b) if a == b => TransitionKind::Identity,
            (BlindExit, _) => TransitionKind::Blocked(""),
            (_, BlindExit) => TransitionKind::Irreversible(""),
            (Client | Exit | Anchor | Nas | Llm, BlindRelay) => TransitionKind::Blocked(""),
            (Admin, Client) | (Client, Admin) => TransitionKind::LocalOnly,
            _ => TransitionKind::SignedMembership,
        }
    }

    /// Expected sibling-service side-effects per
    /// `NodeRoleTaxonomyExtension_2026-06-11.md` §4: each service
    /// kind is independent; deploy when the destination needs a
    /// binary the source does not, undeploy in the opposite case.
    fn expected_service_effects(
        from: RolePreset,
        to: RolePreset,
    ) -> (Vec<ServiceKind>, Vec<ServiceKind>) {
        if from == to || from == RolePreset::BlindExit {
            return (Vec::new(), Vec::new());
        }
        // Blocked blind-relay entries compute no service lifecycle
        // at all — mirror the expected_kind Blocked arm.
        if to == RolePreset::BlindRelay && !matches!(from, RolePreset::Admin | RolePreset::Relay) {
            return (Vec::new(), Vec::new());
        }
        let needs = |preset: RolePreset, kind: ServiceKind| {
            matches!(
                (preset, kind),
                (
                    RolePreset::Relay | RolePreset::Anchor | RolePreset::BlindRelay,
                    ServiceKind::Relay
                ) | (RolePreset::Nas, ServiceKind::Nas)
                    | (RolePreset::Llm, ServiceKind::Llm)
            )
        };
        let mut deploys = Vec::new();
        let mut undeploys = Vec::new();
        for &kind in ServiceKind::all() {
            if !needs(from, kind) && needs(to, kind) {
                deploys.push(kind);
            }
            if needs(from, kind) && !needs(to, kind) {
                undeploys.push(kind);
            }
        }
        (deploys, undeploys)
    }

    fn kind_categories_match(a: &TransitionKind, b: &TransitionKind) -> bool {
        matches!(
            (a, b),
            (TransitionKind::Identity, TransitionKind::Identity)
                | (TransitionKind::LocalOnly, TransitionKind::LocalOnly)
                | (
                    TransitionKind::SignedMembership,
                    TransitionKind::SignedMembership
                )
                | (TransitionKind::Blocked(_), TransitionKind::Blocked(_))
                | (
                    TransitionKind::Irreversible(_),
                    TransitionKind::Irreversible(_)
                )
        )
    }

    #[test]
    fn transition_matrix_matches_taxonomy_doc() {
        let all = [
            RolePreset::Client,
            RolePreset::Admin,
            RolePreset::Exit,
            RolePreset::BlindExit,
            RolePreset::Relay,
            RolePreset::Anchor,
            RolePreset::Nas,
            RolePreset::Llm,
            RolePreset::BlindRelay,
        ];
        let mut mismatches = Vec::new();
        for &from in all.iter() {
            for &to in all.iter() {
                let actual = validate_transition(from, to);
                let expected = expected_kind(from, to);
                if !kind_categories_match(&actual, &expected) {
                    mismatches.push(format!(
                        "({from:?} → {to:?}): expected {expected:?}, got {actual:?}"
                    ));
                }
            }
        }
        assert!(
            mismatches.is_empty(),
            "transition matrix drift from taxonomy doc §5 / extension §4:\n{}",
            mismatches.join("\n")
        );
    }

    #[test]
    fn service_lifecycle_matrix_matches_taxonomy_extension_doc() {
        // Exhaustive 8×8 check of deploy/undeploy side-effects
        // against the expected-result oracle from the taxonomy
        // extension doc §4.
        let mut mismatches = Vec::new();
        for from_entry in ROLE_PRESET_TABLE.iter() {
            for to_entry in ROLE_PRESET_TABLE.iter() {
                let plan = transition_plan(from_entry.preset, to_entry.preset);
                let (expected_deploys, expected_undeploys) =
                    expected_service_effects(from_entry.preset, to_entry.preset);
                if plan.service_deploys != expected_deploys
                    || plan.service_undeploys != expected_undeploys
                {
                    mismatches.push(format!(
                        "({:?} → {:?}): expected deploys {:?} undeploys {:?}, got deploys {:?} undeploys {:?}",
                        from_entry.preset,
                        to_entry.preset,
                        expected_deploys,
                        expected_undeploys,
                        plan.service_deploys,
                        plan.service_undeploys,
                    ));
                }
            }
        }
        assert!(
            mismatches.is_empty(),
            "service lifecycle drift from taxonomy extension doc §4:\n{}",
            mismatches.join("\n")
        );
    }

    // ----- Blind-relay role (BlindRelayRoleDesign §5.1/§6, phase 2) -----

    #[test]
    fn entering_blind_relay_from_incompatible_roles_is_blocked() {
        // §5.1 exclusivity: a node carrying client, exit, anchor, or
        // application-service state cannot become a blind relay by a
        // role edit. (blind_exit → blind_relay is covered by the
        // blind-exit lock-out sweep above.)
        for &from in [
            RolePreset::Client,
            RolePreset::Exit,
            RolePreset::Anchor,
            RolePreset::Nas,
            RolePreset::Llm,
        ]
        .iter()
        {
            let plan = transition_plan(from, RolePreset::BlindRelay);
            assert_eq!(plan.from, from);
            assert_eq!(plan.to, RolePreset::BlindRelay);
            match plan.kind {
                TransitionKind::Blocked(reason) => assert_eq!(
                    reason,
                    "blind_relay must be the node's only mesh duty: step down to admin or relay before entering blind_relay (no client/exit/anchor/service co-location, §5.1)",
                ),
                other => panic!("expected Blocked for {from:?} → blind_relay, got {other:?}"),
            }
            assert!(
                !plan.kind.is_allowed(),
                "{from:?} → blind_relay must not be allowed"
            );
            // Blocked plans compute no side effects and never claim
            // the reinit ceremony.
            assert!(plan.primary_change.is_none());
            assert!(plan.adds_capabilities.is_empty());
            assert!(plan.removes_capabilities.is_empty());
            assert!(plan.service_deploys.is_empty());
            assert!(plan.service_undeploys.is_empty());
            assert!(!plan.requires_privacy_boundary_reinit);
        }
    }

    #[test]
    fn entering_blind_relay_from_compatible_roles_is_signed_membership() {
        // Admin and plain relay are the only privacy-clean entry
        // points (§6.2 enters from a normal, unadvertised relay).
        for &from in [RolePreset::Admin, RolePreset::Relay].iter() {
            let plan = transition_plan(from, RolePreset::BlindRelay);
            assert_eq!(plan.kind, TransitionKind::SignedMembership);
            assert!(plan.kind.is_allowed());
            assert!(plan.kind.requires_owner_signature());
            // The privacy boundary is crossed: phase 2 records the
            // ordered-reinit requirement without performing it.
            assert!(plan.requires_privacy_boundary_reinit);
            assert_eq!(
                plan.primary_change,
                Some((composition_for(from).primary, PrimaryRole::BlindRelay))
            );
        }
        // Service lifecycle: admin must deploy the relay binary
        // (it runs nothing today); plain relay already runs it, so
        // nothing deploys.
        let from_admin = transition_plan(RolePreset::Admin, RolePreset::BlindRelay);
        assert_eq!(from_admin.service_deploys, vec![ServiceKind::Relay]);
        // Capability deltas: admin gains both blind-relay
        // capabilities; plain relay only gains the blind marker.
        assert_eq!(
            from_admin.adds_capabilities,
            vec![Capability::ServesRelay, Capability::BlindRelay]
        );
        let from_relay = transition_plan(RolePreset::Relay, RolePreset::BlindRelay);
        assert_eq!(from_relay.adds_capabilities, vec![Capability::BlindRelay]);
        assert!(from_relay.removes_capabilities.is_empty());
        assert_eq!(from_relay.service_deploys, Vec::<ServiceKind>::new());
    }

    #[test]
    fn leaving_blind_relay_is_reversible_but_marked() {
        // §6.1: blind_relay is NOT factory-reset-irreversible.
        // Leaving it is a signed transition in every direction, and
        // every leaving plan records the privacy-boundary reinit
        // requirement (ceremony itself is phase 4).
        for &to in [
            RolePreset::Client,
            RolePreset::Admin,
            RolePreset::Exit,
            RolePreset::Relay,
            RolePreset::Anchor,
            RolePreset::Nas,
            RolePreset::Llm,
        ]
        .iter()
        {
            let plan = transition_plan(RolePreset::BlindRelay, to);
            assert!(
                plan.kind.is_allowed(),
                "blind_relay → {to:?} must be allowed"
            );
            assert_eq!(
                plan.kind,
                TransitionKind::SignedMembership,
                "blind_relay → {to:?} must require a signed membership record"
            );
            assert!(plan.requires_privacy_boundary_reinit);
            // Leaving always drops the blind marker capability.
            assert!(plan.removes_capabilities.contains(&Capability::BlindRelay));
        }
    }

    #[test]
    fn blind_relay_to_blind_exit_stays_irreversible() {
        // The (_, blind_exit) irreversibility rule keeps precedence
        // over the reversible-leaving rule: the destination change is
        // a factory reset, and the plan still records the privacy
        // boundary crossing.
        let plan = transition_plan(RolePreset::BlindRelay, RolePreset::BlindExit);
        assert!(matches!(plan.kind, TransitionKind::Irreversible(_)));
        assert!(plan.kind.requires_owner_signature());
        assert!(plan.requires_privacy_boundary_reinit);
    }

    #[test]
    fn privacy_boundary_marker_absent_without_blind_relay() {
        // The marker is exclusively a blind-relay signal: no
        // blind-relay-free transition may claim the reinit ceremony.
        for &from in [RolePreset::Client, RolePreset::Admin, RolePreset::Relay].iter() {
            for &to in [RolePreset::Client, RolePreset::Admin, RolePreset::Exit].iter() {
                let plan = transition_plan(from, to);
                assert!(
                    !plan.requires_privacy_boundary_reinit,
                    "{from:?} → {to:?} must not claim the privacy reinit"
                );
            }
        }
        for entry in ROLE_PRESET_TABLE.iter() {
            let plan = transition_plan(entry.preset, entry.preset);
            assert!(!plan.requires_privacy_boundary_reinit);
        }
    }

    #[test]
    fn blind_relay_entry_exclusivity_holds_across_matrix() {
        // Exhaustive guard: no allowed transition may produce a plan
        // whose destination is blind_relay unless the source is one
        // of the two compatible sources (or identity). This is the
        // transition-table mirror of the §5.1 co-location invariant.
        for &from in RolePreset::all().iter() {
            for &to in RolePreset::all().iter() {
                let plan = transition_plan(from, to);
                if plan.kind.is_allowed() && to == RolePreset::BlindRelay && from != to {
                    assert!(
                        matches!(from, RolePreset::Admin | RolePreset::Relay),
                        "allowed entry into blind_relay from incompatible source {from:?}"
                    );
                }
            }
        }
    }

    // ----- Helper predicates -----

    #[test]
    fn is_allowed_excludes_blocked() {
        assert!(!TransitionKind::Blocked("test").is_allowed());
    }

    #[test]
    fn is_allowed_includes_irreversible() {
        // Irreversible IS allowed — just requires explicit ack.
        assert!(TransitionKind::Irreversible("test").is_allowed());
    }

    #[test]
    fn requires_owner_signature_categories() {
        assert!(!TransitionKind::Identity.requires_owner_signature());
        assert!(!TransitionKind::LocalOnly.requires_owner_signature());
        assert!(TransitionKind::SignedMembership.requires_owner_signature());
        assert!(TransitionKind::Irreversible("x").requires_owner_signature());
        // Blocked transitions never reach a signature step; the
        // predicate is irrelevant but conservatively false.
        assert!(!TransitionKind::Blocked("x").requires_owner_signature());
    }

    #[test]
    fn all_presets_returns_nine_unique_entries() {
        let all = RolePreset::all();
        assert_eq!(all.len(), 9);
        let unique: BTreeSet<RolePreset> = all.iter().copied().collect();
        assert_eq!(unique.len(), 9);
    }

    #[test]
    fn descriptions_are_non_empty() {
        for &preset in RolePreset::all().iter() {
            assert!(!preset.description().is_empty());
        }
    }

    // ----- Capability ordering pin (anchor capability list order is significant) -----

    #[test]
    fn anchor_capabilities_in_documented_order() {
        // The order matters for telemetry + audit log output; pin it.
        let comp = composition_for(RolePreset::Anchor);
        assert_eq!(comp.capabilities[0], Capability::AnchorGossipSeed);
        assert_eq!(comp.capabilities[1], Capability::AnchorBundlePull);
        assert_eq!(comp.capabilities[2], Capability::AnchorEnrollmentEndpoint);
        assert_eq!(comp.capabilities[3], Capability::AnchorRelayColocation);
        assert_eq!(
            comp.capabilities[4],
            Capability::AnchorPortMappingAuthoritative
        );
    }
}
