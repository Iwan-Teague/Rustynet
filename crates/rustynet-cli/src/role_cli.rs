//! D12.b — CLI orchestrator for the six user-selectable node roles.
//!
//! Canonical taxonomy:
//! `documents/operations/active/NodeRoleTaxonomy_2026-05-21.md`.
//!
//! This module owns:
//!
//! - The pure planner ([`plan_concrete_actions`]) that maps a
//!   `(current, target)` preset pair to an ordered list of concrete
//!   side-effect actions ([`ConcreteAction`]) the executor must run,
//!   or to a typed blocking outcome.
//!
//! - The status resolver ([`resolve_preset_from_status`]) that maps
//!   the daemon's space-separated `key=value` status line to the
//!   currently-resolved preset.
//!
//! - Stable error categories ([`RoleCliError`]) that the wizard
//!   surface (D12.c) and audit logger (D12.e) can match on without
//!   string-parsing.
//!
//! It deliberately does NOT call any IPC or filesystem APIs directly
//! — those are invoked by the dispatcher in `main.rs`. Keeping this
//! module pure makes the planner exhaustively testable.

use std::path::PathBuf;
use std::str::FromStr;

use rustynet_control::role_presets::{
    Capability, PrimaryRole, RolePreset, TransitionKind, composition_for, transition_plan,
};

/// Stable error-category tag for a [`RoleCliError`]. Used by the
/// D12.e audit logger so audit consumers can match on the
/// categorical shape without parsing the human-readable
/// `user_message()` string.
pub fn role_cli_error_category(err: &RoleCliError) -> &'static str {
    match err {
        RoleCliError::BlindExitImmutable { .. } => "blind_exit_immutable",
        RoleCliError::BlindExitRequiresExplicitAcknowledgement { .. } => {
            "blind_exit_requires_explicit_acknowledgement"
        }
        RoleCliError::RequiresStagedTransition { .. } => "requires_staged_transition",
        RoleCliError::StatusUnreadable { .. } => "status_unreadable",
        RoleCliError::UnknownPreset { .. } => "unknown_preset",
        RoleCliError::UnknownCapability { .. } => "unknown_capability",
    }
}

/// Default audit-log path on Linux. Operator-overridable by setting
/// `RUSTYNET_ROLE_AUDIT_LOG_PATH` in the env.
pub const DEFAULT_ROLE_AUDIT_LOG_PATH: &str = "/var/lib/rustynet/role_transitions.audit.log";

/// Resolve the role-transition audit log path. Honours
/// `RUSTYNET_ROLE_AUDIT_LOG_PATH` first; falls back to
/// [`DEFAULT_ROLE_AUDIT_LOG_PATH`].
pub fn resolve_audit_log_path() -> PathBuf {
    std::env::var_os("RUSTYNET_ROLE_AUDIT_LOG_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_ROLE_AUDIT_LOG_PATH))
}

/// One concrete side-effect the executor must perform. Returned in
/// the order it should be applied: e.g. retract default route
/// (admin-gated) BEFORE writing a new NODE_ROLE=client config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConcreteAction {
    /// `from == to`. Nothing to do.
    NoOp,
    /// Update `NODE_ROLE=<new>` in the daemon env file (default
    /// `/etc/default/rustynetd` on Linux). After the write the
    /// operator must restart `rustynetd.service` so the daemon
    /// picks up the new primary role on next bootstrap.
    WriteNodeRoleEnv {
        new_primary: PrimaryRole,
        env_path: PathBuf,
        restart_required: bool,
    },
    /// Send `IpcCommand::RouteAdvertise("0.0.0.0/0")` to the
    /// running daemon. Activates exit-serving forwarding + NAT on
    /// admin nodes (gated daemon-side to admin only).
    AdvertiseDefaultRoute,
    /// Send `IpcCommand::RouteRetract("0.0.0.0/0")` to the running
    /// daemon. Tears down exit-serving forwarding + NAT.
    /// Counterpart of `AdvertiseDefaultRoute`.
    RetractDefaultRoute,
    /// Install, enable, and start the sibling `rustynet-relay`
    /// service via the existing hardened installer.
    DeployRelayService,
    /// Stop, disable, and remove the sibling `rustynet-relay`
    /// service via the existing hardened installer.
    UndeployRelayService,
}

/// Outcome of [`plan_concrete_actions`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleSetPlan {
    /// Transition is allowed; here is the ordered concrete-action list.
    /// May contain a single action or a compound sequence (e.g.,
    /// retract → write env).
    Allowed {
        from: RolePreset,
        to: RolePreset,
        kind: TransitionKind,
        actions: Vec<ConcreteAction>,
        /// Any additional operator-facing instructions (e.g.
        /// "restart daemon then re-run `role set exit`"). Empty
        /// when the transition is fully self-contained.
        followup_instructions: Vec<String>,
    },
    /// Transition is blocked (e.g. leaving `blind_exit` without
    /// factory reset; capability-schema-dependent role on a build
    /// without D11.a).
    Blocked {
        from: RolePreset,
        to: RolePreset,
        error: RoleCliError,
    },
}

/// Stable, matchable error categories so the wizard surface (D12.c)
/// and audit logger (D12.e) can render or react without parsing
/// strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleCliError {
    /// Leaving `blind_exit` requires factory reset + fresh keys.
    /// String carries a human-readable explanation; the categorical
    /// shape itself is what callers should match on.
    BlindExitImmutable { reason: &'static str },
    /// Becoming `blind_exit` is destructive (wipes node identity);
    /// the caller must pass `accept_irreversible=true`.
    BlindExitRequiresExplicitAcknowledgement { reason: &'static str },
    /// Multi-step transition the operator must perform in stages
    /// (e.g. `client → exit`: switch to admin, restart, then
    /// switch to exit). The orchestrator refuses single-step
    /// execution and surfaces the explicit step sequence.
    RequiresStagedTransition { stages: Vec<String> },
    /// Status line could not be parsed or didn't carry the keys
    /// the planner needs.
    StatusUnreadable { reason: String },
    /// User passed an unknown preset string on the CLI.
    UnknownPreset { raw: String },
    /// User passed an unknown capability string on the CLI.
    UnknownCapability { raw: String },
}

impl RoleCliError {
    pub fn user_message(&self) -> String {
        match self {
            RoleCliError::BlindExitImmutable { reason } => format!(
                "blind_exit is immutable: {reason}. Factory reset + fresh key provisioning is the only path out."
            ),
            RoleCliError::BlindExitRequiresExplicitAcknowledgement { reason } => format!(
                "becoming blind_exit is destructive: {reason}. Pass --accept-irreversible to proceed."
            ),
            RoleCliError::RequiresStagedTransition { stages } => {
                let mut out = String::from(
                    "this transition requires multiple operator steps. Run them in order:\n",
                );
                for (idx, stage) in stages.iter().enumerate() {
                    out.push_str(&format!("  {}. {stage}\n", idx + 1));
                }
                out
            }
            RoleCliError::StatusUnreadable { reason } => {
                format!("could not resolve current role from daemon status: {reason}")
            }
            RoleCliError::UnknownPreset { raw } => format!(
                "unknown role preset {raw:?}. Expected one of: anchor, admin, exit, relay, client, blind_exit"
            ),
            RoleCliError::UnknownCapability { raw } => format!(
                "unknown capability flag {raw:?}. Expected one of: serves_exit, serves_relay, anchor.gossip_seed, anchor.bundle_pull, anchor.enrollment_endpoint, anchor.relay_colocation, anchor.port_mapping_authoritative"
            ),
        }
    }
}

/// Default systemd env-file path used on Linux when an explicit
/// path isn't supplied. Mirrors `DEFAULT_SYSTEMD_ENV_PATH` in
/// `crates/rustynet-cli/src/main.rs`. Kept local to this module so
/// the planner can construct concrete actions without depending on
/// main.rs internals.
pub const DEFAULT_DAEMON_ENV_PATH: &str = "/etc/default/rustynetd";

/// Resolve the current preset from a daemon status line.
///
/// The status line is the space-separated `key=value` body of an
/// `IpcCommand::Status` ok response — see `crates/rustynetd/src/daemon.rs`
/// for the schema. We pull `node_role=<primary>` and
/// `serving_exit_node=<bool>` and resolve to the smallest preset
/// the local primary + serving-state combination matches.
///
/// Capability-bearing presets are resolved by the role planner
/// once signed membership state is available to the caller.
pub fn resolve_preset_from_status(status_line: &str) -> Result<RolePreset, RoleCliError> {
    let primary_raw =
        find_field(status_line, "node_role").ok_or_else(|| RoleCliError::StatusUnreadable {
            reason: "missing node_role in status".to_owned(),
        })?;
    let primary = PrimaryRole::from_str(primary_raw.as_str()).map_err(|err| {
        RoleCliError::StatusUnreadable {
            reason: format!("invalid node_role {primary_raw:?}: {err}"),
        }
    })?;
    let serving_exit = find_field(status_line, "serving_exit_node")
        .map(|v| v == "true")
        .unwrap_or(false);
    Ok(resolve_preset_from_parts(primary, serving_exit))
}

/// Pure mapping from `(primary, serving_exit)` to current preset.
///
/// Pre-D11.a, the only capability the daemon can independently
/// reflect is exit-serving (derived from `advertised_routes`
/// containing `0.0.0.0/0`). `relay` and `anchor` would also
/// require `serves_relay` and `anchor.*` to be present in signed
/// membership state — that schema lands in D11.a.
pub fn resolve_preset_from_parts(primary: PrimaryRole, serving_exit: bool) -> RolePreset {
    match (primary, serving_exit) {
        (PrimaryRole::BlindExit, _) => RolePreset::BlindExit,
        (PrimaryRole::Admin, true) => RolePreset::Exit,
        (PrimaryRole::Admin, false) => RolePreset::Admin,
        (PrimaryRole::Client, _) => RolePreset::Client,
    }
}

fn find_field(status_line: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    status_line
        .split_whitespace()
        .find_map(|field| field.strip_prefix(prefix.as_str()).map(ToString::to_string))
}

/// Pure planner. Maps a `(current, target)` preset pair to either
/// an ordered concrete-action list (for the executor) or a typed
/// blocking error (for surfacing to the operator).
///
/// `accept_irreversible` is the operator's explicit ack to the
/// destructive `* → blind_exit` transition.
///
/// `env_path` is the env-file path the planner will instruct the
/// executor to write. Caller picks the right path per host profile
/// (Linux: `/etc/default/rustynetd`; macOS: user-scoped path).
pub fn plan_concrete_actions(
    current: RolePreset,
    target: RolePreset,
    accept_irreversible: bool,
    env_path: PathBuf,
) -> RoleSetPlan {
    let validator = transition_plan(current, target);

    match validator.kind {
        TransitionKind::Identity => RoleSetPlan::Allowed {
            from: current,
            to: target,
            kind: TransitionKind::Identity,
            actions: vec![ConcreteAction::NoOp],
            followup_instructions: Vec::new(),
        },
        TransitionKind::Blocked(reason) => RoleSetPlan::Blocked {
            from: current,
            to: target,
            error: RoleCliError::BlindExitImmutable { reason },
        },
        TransitionKind::Irreversible(reason) => {
            if !accept_irreversible {
                return RoleSetPlan::Blocked {
                    from: current,
                    to: target,
                    error: RoleCliError::BlindExitRequiresExplicitAcknowledgement { reason },
                };
            }
            // The destructive becoming-blind_exit transition is its
            // own factory-reset orchestration. Today the orchestrator
            // refuses single-step execution and instructs the
            // operator on the staged path (factory reset is queued
            // as separate scope). Re-run after acknowledgement still
            // surfaces the staged guidance — it explicitly does not
            // auto-execute a destructive flow.
            RoleSetPlan::Blocked {
                from: current,
                to: target,
                error: RoleCliError::RequiresStagedTransition {
                    stages: vec![
                        "Factory-reset the node (stop daemon, wipe node identity, clear /var/lib/rustynet/ state)."
                            .to_owned(),
                        "Re-provision the node with NODE_ROLE=blind_exit at first boot via the setup wizard."
                            .to_owned(),
                        "Re-enroll the new BlindExit identity into the mesh via `rustynet enrollment admit` on an admin peer."
                            .to_owned(),
                    ],
                },
            }
        }
        TransitionKind::LocalOnly => {
            // admin ↔ client. No capability change, no IPC needed.
            // Write NODE_ROLE in the env file; daemon must restart.
            let new_primary = composition_for(target).primary;
            RoleSetPlan::Allowed {
                from: current,
                to: target,
                kind: TransitionKind::LocalOnly,
                actions: vec![ConcreteAction::WriteNodeRoleEnv {
                    new_primary,
                    env_path,
                    restart_required: true,
                }],
                followup_instructions: vec![format!(
                    "Restart the daemon so the new primary role takes effect: `systemctl restart rustynetd.service`."
                )],
            }
        }
        TransitionKind::SignedMembership => {
            // Signed-membership transitions mutate signed mesh
            // capabilities. Route advertise/retract and relay
            // service lifecycle are local effects; the signed
            // membership proposal/sign/apply flow remains explicit.
            //
            // The exit cells stay staged when primary-role changes
            // would otherwise combine with default-route mutation:
            //
            // - admin → exit     : advertise 0.0.0.0/0
            // - exit  → admin    : retract 0.0.0.0/0
            // - client → exit    : staged (requires primary change first)
            // - exit   → client  : staged (requires retract THEN primary change)
            match (current, target) {
                (RolePreset::Admin, RolePreset::Exit) => RoleSetPlan::Allowed {
                    from: current,
                    to: target,
                    kind: TransitionKind::SignedMembership,
                    actions: vec![ConcreteAction::AdvertiseDefaultRoute],
                    followup_instructions: vec![
                        "Issue per-client signed assignment bundles naming this node as `--exit-node-id` so peers can select it (`rustynet assignment issue`)."
                            .to_owned(),
                    ],
                },
                (RolePreset::Exit, RolePreset::Admin) => RoleSetPlan::Allowed {
                    from: current,
                    to: target,
                    kind: TransitionKind::SignedMembership,
                    actions: vec![ConcreteAction::RetractDefaultRoute],
                    followup_instructions: vec![
                        "Re-issue any per-client assignment bundles that previously named this node as their exit so peers don't fail closed on a stale exit reference."
                            .to_owned(),
                    ],
                },
                (RolePreset::Client, RolePreset::Exit) => RoleSetPlan::Blocked {
                    from: current,
                    to: target,
                    error: RoleCliError::RequiresStagedTransition {
                        stages: vec![
                            "Run `rustynet role set admin` to elevate the primary role.".to_owned(),
                            "Restart the daemon so the new primary role takes effect."
                                .to_owned(),
                            "Run `rustynet role set exit` once the daemon reports `node_role=admin` to advertise 0.0.0.0/0 and activate exit-serving."
                                .to_owned(),
                        ],
                    },
                },
                (RolePreset::Exit, RolePreset::Client) => RoleSetPlan::Blocked {
                    from: current,
                    to: target,
                    error: RoleCliError::RequiresStagedTransition {
                        stages: vec![
                            "Run `rustynet role set admin` to retract 0.0.0.0/0 (this drops exit-serving).".to_owned(),
                            "Run `rustynet role set client` to lower the primary role.".to_owned(),
                            "Restart the daemon so the new primary role takes effect.".to_owned(),
                        ],
                    },
                },
                _ => {
                    let mut actions = Vec::new();
                    if let Some((_, new_primary)) = validator.primary_change {
                        actions.push(ConcreteAction::WriteNodeRoleEnv {
                            new_primary,
                            env_path,
                            restart_required: true,
                        });
                    }
                    if validator.requires_relay_deploy {
                        actions.push(ConcreteAction::DeployRelayService);
                    }
                    if validator.requires_relay_undeploy {
                        actions.push(ConcreteAction::UndeployRelayService);
                    }
                    if actions.is_empty() {
                        actions.push(ConcreteAction::NoOp);
                    }

                    let mut followup_instructions = vec![
                        format!(
                            "Emit, sign, and apply a membership capability update for this node before relying on the new {target} role."
                        ),
                    ];
                    if target == RolePreset::Anchor {
                        followup_instructions.push(
                            "Use `rustynet anchor advertise --node-id <id> --capabilities gossip_seed,bundle_pull,enrollment_endpoint,relay_colocation,port_mapping_authoritative` to build the unsigned update record."
                                .to_owned(),
                        );
                    }
                    if validator.primary_change.is_some() {
                        followup_instructions.push(
                            "Restart the daemon so the new primary role takes effect: `systemctl restart rustynetd.service`."
                                .to_owned(),
                        );
                    }

                    RoleSetPlan::Allowed {
                        from: current,
                        to: target,
                        kind: TransitionKind::SignedMembership,
                        actions,
                        followup_instructions,
                    }
                }
            }
        }
    }
}

/// Build the human-readable role-list output for `rustynet role list`.
/// Pure function so the wizard surface (D12.c) can re-use it.
pub fn render_role_list() -> String {
    let mut lines = vec!["Available node roles:".to_owned()];
    for &preset in RolePreset::all().iter() {
        lines.push(format!("  {} — {}", preset.as_str(), preset.description()));
    }
    lines.push(String::new());
    lines.push(
        "Use `rustynet role set <preset>` to change the active role on this device.".to_owned(),
    );
    lines.push("Use `rustynet role status` to see the current preset.".to_owned());
    lines.push(
        "Use `rustynet role transition-check --to <preset>` to preview a transition without applying it."
            .to_owned(),
    );
    lines.join("\n")
}

/// Format a transition-check result for operator output without
/// executing any side-effects.
pub fn render_transition_check(plan: &RoleSetPlan) -> String {
    match plan {
        RoleSetPlan::Allowed {
            from,
            to,
            kind,
            actions,
            followup_instructions,
        } => {
            let mut out = format!("Transition: {from} → {to}\n");
            out.push_str(&format!("Kind: {}\n", render_kind(kind)));
            out.push_str("Concrete actions (in order):\n");
            for (idx, action) in actions.iter().enumerate() {
                out.push_str(&format!("  {}. {}\n", idx + 1, render_action(action)));
            }
            if !followup_instructions.is_empty() {
                out.push_str("Operator follow-up:\n");
                for instruction in followup_instructions {
                    out.push_str(&format!("  - {instruction}\n"));
                }
            }
            out
        }
        RoleSetPlan::Blocked { from, to, error } => {
            let mut out = format!("Transition: {from} → {to}\nBlocked: ");
            out.push_str(&error.user_message());
            out.push('\n');
            out
        }
    }
}

fn render_kind(kind: &TransitionKind) -> &'static str {
    match kind {
        TransitionKind::Identity => "identity (no-op)",
        TransitionKind::LocalOnly => "local-only (config write + daemon restart)",
        TransitionKind::SignedMembership => "signed-membership (capability change)",
        TransitionKind::Blocked(_) => "blocked",
        TransitionKind::Irreversible(_) => "irreversible (destructive)",
    }
}

fn render_action(action: &ConcreteAction) -> String {
    match action {
        ConcreteAction::NoOp => "no-op".to_owned(),
        ConcreteAction::WriteNodeRoleEnv {
            new_primary,
            env_path,
            restart_required,
        } => format!(
            "write NODE_ROLE={new_primary} to {} (daemon restart {})",
            env_path.display(),
            if *restart_required {
                "required"
            } else {
                "optional"
            }
        ),
        ConcreteAction::AdvertiseDefaultRoute => "send IPC: route advertise 0.0.0.0/0".to_owned(),
        ConcreteAction::RetractDefaultRoute => "send IPC: route retract 0.0.0.0/0".to_owned(),
        ConcreteAction::DeployRelayService => "install+enable rustynet-relay.service".to_owned(),
        ConcreteAction::UndeployRelayService => "disable+remove rustynet-relay.service".to_owned(),
    }
}

/// Parse a capability string from the CLI. Wraps
/// `Capability::from_str` with a typed error category so the
/// dispatcher can match without parsing.
pub fn parse_capability_arg(raw: &str) -> Result<Capability, RoleCliError> {
    Capability::from_str(raw).map_err(|_| RoleCliError::UnknownCapability {
        raw: raw.to_owned(),
    })
}

/// Parse a preset string from the CLI with typed error.
pub fn parse_preset_arg(raw: &str) -> Result<RolePreset, RoleCliError> {
    RolePreset::from_str(raw).map_err(|_| RoleCliError::UnknownPreset {
        raw: raw.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_path() -> PathBuf {
        PathBuf::from("/etc/default/rustynetd")
    }

    // ----- Status resolver -----

    #[test]
    fn resolve_admin_no_exit() {
        let preset = resolve_preset_from_parts(PrimaryRole::Admin, false);
        assert_eq!(preset, RolePreset::Admin);
    }

    #[test]
    fn resolve_admin_serving_exit() {
        let preset = resolve_preset_from_parts(PrimaryRole::Admin, true);
        assert_eq!(preset, RolePreset::Exit);
    }

    #[test]
    fn resolve_client_ignores_exit_flag() {
        // A Client primary cannot serve exit (daemon rejects
        // route advertise from client). Even if the status line
        // somehow carries serving_exit_node=true alongside
        // node_role=client, the resolver maps to Client because
        // that's the source-of-truth axis.
        assert_eq!(
            resolve_preset_from_parts(PrimaryRole::Client, false),
            RolePreset::Client
        );
        assert_eq!(
            resolve_preset_from_parts(PrimaryRole::Client, true),
            RolePreset::Client
        );
    }

    #[test]
    fn resolve_blind_exit_always_blind_exit() {
        assert_eq!(
            resolve_preset_from_parts(PrimaryRole::BlindExit, true),
            RolePreset::BlindExit
        );
        assert_eq!(
            resolve_preset_from_parts(PrimaryRole::BlindExit, false),
            RolePreset::BlindExit
        );
    }

    #[test]
    fn resolve_from_real_status_line_admin_no_exit() {
        let status = "node_id=peer-1 node_role=admin state=Direct generation=4 exit_node= serving_exit_node=false other_field=value";
        let preset = resolve_preset_from_status(status).unwrap();
        assert_eq!(preset, RolePreset::Admin);
    }

    #[test]
    fn resolve_from_real_status_line_serving_exit() {
        let status = "node_id=peer-1 node_role=admin serving_exit_node=true other=value";
        let preset = resolve_preset_from_status(status).unwrap();
        assert_eq!(preset, RolePreset::Exit);
    }

    #[test]
    fn resolve_from_status_missing_node_role_errors() {
        let status = "node_id=peer-1 serving_exit_node=false";
        let err = resolve_preset_from_status(status).unwrap_err();
        assert!(matches!(err, RoleCliError::StatusUnreadable { .. }));
    }

    #[test]
    fn resolve_from_status_invalid_node_role_errors() {
        let status = "node_id=peer-1 node_role=supernode serving_exit_node=false";
        let err = resolve_preset_from_status(status).unwrap_err();
        assert!(matches!(err, RoleCliError::StatusUnreadable { .. }));
    }

    // ----- Planner: identity -----

    #[test]
    fn identity_plan_for_client() {
        let plan = plan_concrete_actions(RolePreset::Client, RolePreset::Client, false, env_path());
        match plan {
            RoleSetPlan::Allowed { kind, actions, .. } => {
                assert_eq!(kind, TransitionKind::Identity);
                assert_eq!(actions, vec![ConcreteAction::NoOp]);
            }
            other => panic!("expected Allowed Identity, got {other:?}"),
        }
    }

    // ----- Planner: local-only (admin ↔ client) -----

    #[test]
    fn admin_to_client_plans_env_write() {
        let plan = plan_concrete_actions(RolePreset::Admin, RolePreset::Client, false, env_path());
        match plan {
            RoleSetPlan::Allowed {
                kind,
                actions,
                followup_instructions,
                ..
            } => {
                assert_eq!(kind, TransitionKind::LocalOnly);
                assert_eq!(actions.len(), 1);
                match &actions[0] {
                    ConcreteAction::WriteNodeRoleEnv {
                        new_primary,
                        restart_required,
                        ..
                    } => {
                        assert_eq!(*new_primary, PrimaryRole::Client);
                        assert!(*restart_required);
                    }
                    other => panic!("expected WriteNodeRoleEnv, got {other:?}"),
                }
                assert!(!followup_instructions.is_empty());
            }
            other => panic!("expected Allowed LocalOnly, got {other:?}"),
        }
    }

    #[test]
    fn client_to_admin_plans_env_write() {
        let plan = plan_concrete_actions(RolePreset::Client, RolePreset::Admin, false, env_path());
        match plan {
            RoleSetPlan::Allowed { kind, actions, .. } => {
                assert_eq!(kind, TransitionKind::LocalOnly);
                match &actions[0] {
                    ConcreteAction::WriteNodeRoleEnv { new_primary, .. } => {
                        assert_eq!(*new_primary, PrimaryRole::Admin);
                    }
                    other => panic!("expected WriteNodeRoleEnv, got {other:?}"),
                }
            }
            other => panic!("expected Allowed LocalOnly, got {other:?}"),
        }
    }

    // ----- Planner: admin ↔ exit (signed-membership, today's surface) -----

    #[test]
    fn admin_to_exit_advertises_default_route() {
        let plan = plan_concrete_actions(RolePreset::Admin, RolePreset::Exit, false, env_path());
        match plan {
            RoleSetPlan::Allowed { kind, actions, .. } => {
                assert_eq!(kind, TransitionKind::SignedMembership);
                assert_eq!(actions, vec![ConcreteAction::AdvertiseDefaultRoute]);
            }
            other => panic!("expected Allowed SignedMembership, got {other:?}"),
        }
    }

    #[test]
    fn exit_to_admin_retracts_default_route() {
        let plan = plan_concrete_actions(RolePreset::Exit, RolePreset::Admin, false, env_path());
        match plan {
            RoleSetPlan::Allowed { kind, actions, .. } => {
                assert_eq!(kind, TransitionKind::SignedMembership);
                assert_eq!(actions, vec![ConcreteAction::RetractDefaultRoute]);
            }
            other => panic!("expected Allowed SignedMembership, got {other:?}"),
        }
    }

    // ----- Planner: staged multi-step transitions -----

    #[test]
    fn client_to_exit_requires_staged_transition() {
        let plan = plan_concrete_actions(RolePreset::Client, RolePreset::Exit, false, env_path());
        match plan {
            RoleSetPlan::Blocked { error, .. } => {
                assert!(matches!(
                    error,
                    RoleCliError::RequiresStagedTransition { .. }
                ));
            }
            other => panic!("expected Blocked RequiresStagedTransition, got {other:?}"),
        }
    }

    #[test]
    fn exit_to_client_requires_staged_transition() {
        let plan = plan_concrete_actions(RolePreset::Exit, RolePreset::Client, false, env_path());
        assert!(matches!(
            plan,
            RoleSetPlan::Blocked {
                error: RoleCliError::RequiresStagedTransition { .. },
                ..
            }
        ));
    }

    // ----- Planner: blind_exit -----

    #[test]
    fn leaving_blind_exit_is_blocked() {
        for &target in &[
            RolePreset::Client,
            RolePreset::Admin,
            RolePreset::Exit,
            RolePreset::Relay,
            RolePreset::Anchor,
        ] {
            let plan = plan_concrete_actions(RolePreset::BlindExit, target, false, env_path());
            match plan {
                RoleSetPlan::Blocked { error, .. } => {
                    assert!(matches!(error, RoleCliError::BlindExitImmutable { .. }));
                }
                other => panic!("expected Blocked for BlindExit → {target:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn entering_blind_exit_without_ack_is_blocked() {
        let plan =
            plan_concrete_actions(RolePreset::Admin, RolePreset::BlindExit, false, env_path());
        assert!(matches!(
            plan,
            RoleSetPlan::Blocked {
                error: RoleCliError::BlindExitRequiresExplicitAcknowledgement { .. },
                ..
            }
        ));
    }

    #[test]
    fn entering_blind_exit_with_ack_still_returns_staged_path() {
        // Even with explicit ack, the orchestrator refuses
        // single-step destructive execution and surfaces the
        // staged factory-reset path. Auto-execution is a
        // separate scope.
        let plan =
            plan_concrete_actions(RolePreset::Admin, RolePreset::BlindExit, true, env_path());
        match plan {
            RoleSetPlan::Blocked {
                error: RoleCliError::RequiresStagedTransition { stages },
                ..
            } => {
                assert!(!stages.is_empty());
                assert!(stages.iter().any(|s| s.to_lowercase().contains("factory")));
            }
            other => panic!("expected staged-transition for *, got {other:?}"),
        }
    }

    #[test]
    fn identity_to_blind_exit_is_noop_even_without_ack() {
        // BlindExit → BlindExit is Identity, not destructive. No
        // acknowledgement needed.
        let plan = plan_concrete_actions(
            RolePreset::BlindExit,
            RolePreset::BlindExit,
            false,
            env_path(),
        );
        match plan {
            RoleSetPlan::Allowed { kind, .. } => {
                assert_eq!(kind, TransitionKind::Identity);
            }
            other => panic!("expected Identity for blind_exit → blind_exit, got {other:?}"),
        }
    }

    // ----- Planner: relay/anchor unlocked by D11.a -----

    #[test]
    fn target_relay_deploys_relay_service() {
        for &from in &[RolePreset::Client, RolePreset::Admin, RolePreset::Exit] {
            let plan = plan_concrete_actions(from, RolePreset::Relay, false, env_path());
            match plan {
                RoleSetPlan::Allowed { actions, .. } => {
                    assert!(actions.contains(&ConcreteAction::DeployRelayService));
                }
                other => panic!("expected relay transition allowed, got {other:?}"),
            }
        }
    }

    #[test]
    fn target_anchor_deploys_relay_service() {
        let plan = plan_concrete_actions(RolePreset::Admin, RolePreset::Anchor, false, env_path());
        match plan {
            RoleSetPlan::Allowed {
                actions,
                followup_instructions,
                ..
            } => {
                assert!(actions.contains(&ConcreteAction::DeployRelayService));
                assert!(
                    followup_instructions
                        .iter()
                        .any(|line| line.contains("anchor advertise"))
                );
            }
            other => panic!("expected anchor transition allowed, got {other:?}"),
        }
    }

    #[test]
    fn current_relay_to_admin_undeploys_relay_service() {
        let plan = plan_concrete_actions(RolePreset::Relay, RolePreset::Admin, false, env_path());
        match plan {
            RoleSetPlan::Allowed { actions, .. } => {
                assert!(actions.contains(&ConcreteAction::UndeployRelayService));
            }
            other => panic!("expected relay departure allowed, got {other:?}"),
        }
    }

    // ----- Argument parsers -----

    #[test]
    fn parse_preset_arg_round_trip() {
        for &preset in RolePreset::all().iter() {
            let parsed = parse_preset_arg(preset.as_str()).unwrap();
            assert_eq!(parsed, preset);
        }
    }

    #[test]
    fn parse_preset_arg_unknown() {
        let err = parse_preset_arg("hub").unwrap_err();
        assert!(matches!(err, RoleCliError::UnknownPreset { .. }));
    }

    #[test]
    fn parse_capability_arg_round_trip() {
        let parsed = parse_capability_arg("serves_exit").unwrap();
        assert_eq!(parsed, Capability::ServesExit);
        let parsed = parse_capability_arg("anchor.gossip_seed").unwrap();
        assert_eq!(parsed, Capability::AnchorGossipSeed);
    }

    #[test]
    fn parse_capability_arg_unknown() {
        let err = parse_capability_arg("not_a_cap").unwrap_err();
        assert!(matches!(err, RoleCliError::UnknownCapability { .. }));
    }

    // ----- Rendering (smoke) -----

    #[test]
    fn render_role_list_mentions_every_preset() {
        let listing = render_role_list();
        for &preset in RolePreset::all().iter() {
            assert!(
                listing.contains(preset.as_str()),
                "role list missing {}: {listing}",
                preset.as_str()
            );
        }
    }

    #[test]
    fn render_transition_check_allowed_includes_action() {
        let plan = plan_concrete_actions(RolePreset::Admin, RolePreset::Exit, false, env_path());
        let rendered = render_transition_check(&plan);
        assert!(rendered.contains("Admin → Exit") || rendered.contains("admin → exit"));
        assert!(rendered.to_lowercase().contains("advertise"));
    }

    #[test]
    fn render_transition_check_blocked_includes_reason() {
        let plan =
            plan_concrete_actions(RolePreset::Admin, RolePreset::BlindExit, false, env_path());
        let rendered = render_transition_check(&plan);
        assert!(rendered.contains("Blocked"));
        assert!(rendered.contains("blind_exit"));
    }

    // ----- Exhaustive coverage of today's 4-role surface -----

    /// Pin every (current, target) cell for the four roles that
    /// the pre-D11.a surface supports. Drift between the planner
    /// and this expectation table is a test failure.
    #[test]
    fn pre_d11a_surface_matrix() {
        use ExpectedPlanShape::*;
        let cases: &[(RolePreset, RolePreset, ExpectedPlanShape)] = &[
            (RolePreset::Client, RolePreset::Client, Identity),
            (RolePreset::Client, RolePreset::Admin, LocalOnly),
            (RolePreset::Client, RolePreset::Exit, Staged),
            (RolePreset::Client, RolePreset::BlindExit, NeedsAck),
            (RolePreset::Admin, RolePreset::Client, LocalOnly),
            (RolePreset::Admin, RolePreset::Admin, Identity),
            (RolePreset::Admin, RolePreset::Exit, Advertise),
            (RolePreset::Admin, RolePreset::BlindExit, NeedsAck),
            (RolePreset::Exit, RolePreset::Client, Staged),
            (RolePreset::Exit, RolePreset::Admin, Retract),
            (RolePreset::Exit, RolePreset::Exit, Identity),
            (RolePreset::Exit, RolePreset::BlindExit, NeedsAck),
            (RolePreset::BlindExit, RolePreset::Client, BlindExitLocked),
            (RolePreset::BlindExit, RolePreset::Admin, BlindExitLocked),
            (RolePreset::BlindExit, RolePreset::Exit, BlindExitLocked),
            (RolePreset::BlindExit, RolePreset::BlindExit, Identity),
        ];
        for &(from, to, ref expected) in cases {
            let plan = plan_concrete_actions(from, to, false, env_path());
            assert!(
                expected.matches(&plan),
                "({from:?} → {to:?}): expected {expected:?}, got {plan:?}"
            );
        }
    }

    #[derive(Debug)]
    enum ExpectedPlanShape {
        Identity,
        LocalOnly,
        Advertise,
        Retract,
        Staged,
        NeedsAck,
        BlindExitLocked,
    }

    impl ExpectedPlanShape {
        fn matches(&self, plan: &RoleSetPlan) -> bool {
            match (self, plan) {
                (
                    ExpectedPlanShape::Identity,
                    RoleSetPlan::Allowed {
                        kind: TransitionKind::Identity,
                        ..
                    },
                ) => true,
                (
                    ExpectedPlanShape::LocalOnly,
                    RoleSetPlan::Allowed {
                        kind: TransitionKind::LocalOnly,
                        actions,
                        ..
                    },
                ) => matches!(
                    actions.as_slice(),
                    [ConcreteAction::WriteNodeRoleEnv { .. }]
                ),
                (
                    ExpectedPlanShape::Advertise,
                    RoleSetPlan::Allowed {
                        kind: TransitionKind::SignedMembership,
                        actions,
                        ..
                    },
                ) => actions.as_slice() == [ConcreteAction::AdvertiseDefaultRoute],
                (
                    ExpectedPlanShape::Retract,
                    RoleSetPlan::Allowed {
                        kind: TransitionKind::SignedMembership,
                        actions,
                        ..
                    },
                ) => actions.as_slice() == [ConcreteAction::RetractDefaultRoute],
                (
                    ExpectedPlanShape::Staged,
                    RoleSetPlan::Blocked {
                        error: RoleCliError::RequiresStagedTransition { .. },
                        ..
                    },
                ) => true,
                (
                    ExpectedPlanShape::NeedsAck,
                    RoleSetPlan::Blocked {
                        error: RoleCliError::BlindExitRequiresExplicitAcknowledgement { .. },
                        ..
                    },
                ) => true,
                (
                    ExpectedPlanShape::BlindExitLocked,
                    RoleSetPlan::Blocked {
                        error: RoleCliError::BlindExitImmutable { .. },
                        ..
                    },
                ) => true,
                _ => false,
            }
        }
    }
}
