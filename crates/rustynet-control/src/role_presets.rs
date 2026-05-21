//! Node role taxonomy: six user-selectable per-device presets.
//!
//! Canonical design:
//! `documents/operations/active/NodeRoleTaxonomy_2026-05-21.md`.
//!
//! Two-axis internal model (kept separate by design):
//!
//! - **Axis 1** — primary local role
//!   ([`PrimaryRole`]: `Admin | Client | BlindExit`). Mirrors
//!   `crates/rustynetd/src/daemon.rs::NodeRole`. Controls local
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
//! some are irreversible (anything involving `blind_exit`).

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
        }
    }

    /// All presets in canonical order. Wizard surfaces should
    /// present in this order.
    pub fn all() -> &'static [RolePreset; 6] {
        &[
            RolePreset::Anchor,
            RolePreset::Admin,
            RolePreset::Exit,
            RolePreset::Relay,
            RolePreset::Client,
            RolePreset::BlindExit,
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
            other => Err(format!(
                "invalid role preset: {other:?} (expected one of: anchor, admin, exit, relay, client, blind_exit)"
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
}

impl PrimaryRole {
    pub fn as_str(self) -> &'static str {
        match self {
            PrimaryRole::Client => "client",
            PrimaryRole::Admin => "admin",
            PrimaryRole::BlindExit => "blind_exit",
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
            other => Err(format!(
                "invalid primary role: {other:?} (expected client, admin, or blind_exit)"
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
pub const ROLE_PRESET_TABLE: [RolePresetComposition; 6] = [
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
    /// True if the transition requires deploying the
    /// `rustynet-relay` sibling service (source had no relay
    /// capability; destination does).
    pub requires_relay_deploy: bool,
    /// True if the transition requires undeploying the
    /// `rustynet-relay` sibling service (source had relay
    /// capability; destination does not).
    pub requires_relay_undeploy: bool,
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
            requires_relay_deploy: false,
            requires_relay_undeploy: false,
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
            requires_relay_deploy: false,
            requires_relay_undeploy: false,
        };
    }

    // Compute capability deltas.
    let from_caps: BTreeSet<Capability> = from_comp.capabilities.iter().copied().collect();
    let to_caps: BTreeSet<Capability> = to_comp.capabilities.iter().copied().collect();
    let adds: Vec<Capability> = to_caps.difference(&from_caps).copied().collect();
    let removes: Vec<Capability> = from_caps.difference(&to_caps).copied().collect();

    let from_needs_relay = capabilities_require_relay_binary(from_comp.capabilities);
    let to_needs_relay = capabilities_require_relay_binary(to_comp.capabilities);
    let requires_relay_deploy = !from_needs_relay && to_needs_relay;
    let requires_relay_undeploy = from_needs_relay && !to_needs_relay;

    let primary_change = if from_comp.primary != to_comp.primary {
        Some((from_comp.primary, to_comp.primary))
    } else {
        None
    };

    // Becoming BlindExit is destructive: wipes existing identity
    // and re-enrolls fresh. Allowed but irreversible — the wizard
    // must confirm with typed acknowledgement.
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
        requires_relay_deploy,
        requires_relay_undeploy,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- Preset table integrity -----

    #[test]
    fn preset_table_has_exactly_six_entries() {
        assert_eq!(ROLE_PRESET_TABLE.len(), 6);
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
        ]
        .iter()
        {
            let s = primary.as_str();
            let parsed: PrimaryRole = s.parse().expect("round trip");
            assert_eq!(parsed, primary);
        }
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
        ]
        .iter()
        {
            let s = cap.as_str();
            let parsed: Capability = s.parse().expect("round trip");
            assert_eq!(parsed, cap);
        }
    }

    #[test]
    fn capability_rejects_unknown() {
        assert!("super_cap".parse::<Capability>().is_err());
        assert!("anchor.bogus".parse::<Capability>().is_err());
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

    // ----- Identity transitions -----

    #[test]
    fn identity_transition_for_every_preset() {
        for entry in ROLE_PRESET_TABLE.iter() {
            let plan = transition_plan(entry.preset, entry.preset);
            assert_eq!(plan.kind, TransitionKind::Identity);
            assert!(plan.adds_capabilities.is_empty());
            assert!(plan.removes_capabilities.is_empty());
            assert!(plan.primary_change.is_none());
            assert!(!plan.requires_relay_deploy);
            assert!(!plan.requires_relay_undeploy);
        }
    }

    // ----- Blocked transitions (from BlindExit) -----

    #[test]
    fn blind_exit_to_anything_else_is_blocked() {
        for &to in [
            RolePreset::Client,
            RolePreset::Admin,
            RolePreset::Exit,
            RolePreset::Relay,
            RolePreset::Anchor,
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

    // ----- Irreversible transitions (into BlindExit) -----

    #[test]
    fn anything_to_blind_exit_is_irreversible() {
        for &from in [
            RolePreset::Client,
            RolePreset::Admin,
            RolePreset::Exit,
            RolePreset::Relay,
            RolePreset::Anchor,
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
    fn admin_to_client_is_local_only() {
        let plan = transition_plan(RolePreset::Admin, RolePreset::Client);
        assert_eq!(plan.kind, TransitionKind::LocalOnly);
        assert!(plan.adds_capabilities.is_empty());
        assert!(plan.removes_capabilities.is_empty());
        assert_eq!(
            plan.primary_change,
            Some((PrimaryRole::Admin, PrimaryRole::Client))
        );
        assert!(!plan.requires_relay_deploy);
        assert!(!plan.requires_relay_undeploy);
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
        assert!(!plan.requires_relay_deploy);
        assert!(!plan.requires_relay_undeploy);
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
    fn admin_to_relay_requires_deploy() {
        let plan = transition_plan(RolePreset::Admin, RolePreset::Relay);
        assert_eq!(plan.kind, TransitionKind::SignedMembership);
        assert_eq!(plan.adds_capabilities, vec![Capability::ServesRelay]);
        assert!(plan.requires_relay_deploy);
        assert!(!plan.requires_relay_undeploy);
    }

    #[test]
    fn relay_to_admin_requires_undeploy() {
        let plan = transition_plan(RolePreset::Relay, RolePreset::Admin);
        assert_eq!(plan.kind, TransitionKind::SignedMembership);
        assert_eq!(plan.removes_capabilities, vec![Capability::ServesRelay]);
        assert!(!plan.requires_relay_deploy);
        assert!(plan.requires_relay_undeploy);
    }

    #[test]
    fn admin_to_anchor_requires_deploy() {
        let plan = transition_plan(RolePreset::Admin, RolePreset::Anchor);
        assert_eq!(plan.kind, TransitionKind::SignedMembership);
        assert!(plan.requires_relay_deploy);
        assert!(!plan.requires_relay_undeploy);
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
        assert!(plan.requires_relay_undeploy);
        assert!(!plan.requires_relay_deploy);
        assert_eq!(plan.removes_capabilities.len(), 5);
    }

    #[test]
    fn relay_to_anchor_no_relay_lifecycle_change() {
        let plan = transition_plan(RolePreset::Relay, RolePreset::Anchor);
        assert_eq!(plan.kind, TransitionKind::SignedMembership);
        // Both presets keep the relay binary running. AnchorRelayColocation
        // replaces ServesRelay; from a binary-lifecycle standpoint, no
        // deploy/undeploy is needed.
        assert!(!plan.requires_relay_deploy);
        assert!(!plan.requires_relay_undeploy);
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
        assert!(!plan.requires_relay_deploy);
        assert!(!plan.requires_relay_undeploy);
        assert!(plan.adds_capabilities.contains(&Capability::ServesRelay));
        assert!(
            plan.removes_capabilities
                .contains(&Capability::AnchorRelayColocation)
        );
    }

    // ----- Exhaustive matrix coverage (every from × to cell) -----

    /// Reference transition matrix mirrored from
    /// `documents/operations/active/NodeRoleTaxonomy_2026-05-21.md` §5.
    /// Drift between this table and `validate_transition` is a test
    /// failure and a docs-vs-code synchronisation defect.
    fn expected_kind(from: RolePreset, to: RolePreset) -> TransitionKind {
        use RolePreset::*;
        match (from, to) {
            (a, b) if a == b => TransitionKind::Identity,
            (BlindExit, _) => TransitionKind::Blocked(""),
            (_, BlindExit) => TransitionKind::Irreversible(""),
            (Admin, Client) | (Client, Admin) => TransitionKind::LocalOnly,
            _ => TransitionKind::SignedMembership,
        }
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
            "transition matrix drift from taxonomy doc §5:\n{}",
            mismatches.join("\n")
        );
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
    fn all_presets_returns_six_unique_entries() {
        let all = RolePreset::all();
        assert_eq!(all.len(), 6);
        let unique: BTreeSet<RolePreset> = all.iter().copied().collect();
        assert_eq!(unique.len(), 6);
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
