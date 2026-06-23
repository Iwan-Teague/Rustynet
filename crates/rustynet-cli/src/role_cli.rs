//! D12.b — CLI orchestrator for the eight user-selectable node roles.
//!
//! Canonical taxonomy:
//! `documents/operations/active/NodeRoleTaxonomy_2026-05-21.md`,
//! extended by
//! `documents/operations/active/NodeRoleTaxonomyExtension_2026-06-11.md`
//! (service-hosting presets `nas` and `llm`).
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
    Capability, PrimaryRole, RolePreset, ServiceKind, TransitionKind, composition_for,
    transition_plan,
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
/// `RUSTYNET_ROLE_AUDIT_LOG_PATH` in the env. Per-OS defaults live
/// in [`platform_default_role_audit_log_path`] so a fresh-install
/// daemon on each OS lands at the correct path without needing the
/// operator to set the env var.
pub const DEFAULT_ROLE_AUDIT_LOG_PATH: &str = "/var/lib/rustynet/role_transitions.audit.log";

/// Track B Phase 17 — per-OS default for the role-transition audit
/// log path. Mirrors the install layouts the live-lab validator
/// uses (`/usr/local/var/rustynet/` on macOS,
/// `C:\ProgramData\RustyNet\` on Windows). Each invocation of
/// [`resolve_audit_log_path`] consults this when
/// `RUSTYNET_ROLE_AUDIT_LOG_PATH` is not set so the daemon writes
/// to the same file the live-lab + operator tooling reads.
pub fn platform_default_role_audit_log_path() -> &'static str {
    if cfg!(target_os = "macos") {
        "/usr/local/var/rustynet/role_transitions.audit.log"
    } else if cfg!(target_os = "windows") {
        r"C:\ProgramData\RustyNet\role_transitions.audit.log"
    } else {
        DEFAULT_ROLE_AUDIT_LOG_PATH
    }
}

/// Resolve the role-transition audit log path. Honours
/// `RUSTYNET_ROLE_AUDIT_LOG_PATH` first; falls back to
/// [`platform_default_role_audit_log_path`] (per-OS default).
pub fn resolve_audit_log_path() -> PathBuf {
    std::env::var_os("RUSTYNET_ROLE_AUDIT_LOG_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(platform_default_role_audit_log_path()))
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
    /// Track B Step 3 (B1.4) — install / enable / start the
    /// rustynet-exit preflight (sibling systemd unit on Linux,
    /// launchd plist on macOS, IPv4 forwarding script on Windows)
    /// via the platform-specific hardened installer. Used by the
    /// role-transition orchestrator when entering an exit-bearing
    /// preset. Dispatch lives in `execute_platform_exit_service_action`
    /// in `main.rs`.
    DeployExitService,
    /// Counterpart of [`Self::DeployExitService`]. Stop and remove the
    /// exit preflight via the platform-specific installer when
    /// leaving an exit-bearing preset.
    UndeployExitService,
    /// Install, enable, and start the sibling `rustynet-nas`
    /// service (tunnel-only storage endpoint). Deploy precedes the
    /// signed `serves_nas` advertisement (deploy-before-advertise).
    DeployNasService,
    /// Stop, disable, and remove the sibling `rustynet-nas`
    /// service. Undeploy (after session severance) precedes the
    /// signed `serves_nas` revocation (undeploy-before-revoke).
    UndeployNasService,
    /// Install, enable, and start the sibling
    /// `rustynet-llm-gateway` service (tunnel-only inference
    /// endpoint). Deploy precedes the signed `serves_llm`
    /// advertisement.
    DeployLlmService,
    /// Stop, disable, and remove the sibling
    /// `rustynet-llm-gateway` service. Undeploy (after stream
    /// severance) precedes the signed `serves_llm` revocation.
    UndeployLlmService,
}

/// Map a sibling-service kind to its deploy action.
fn deploy_action_for(kind: ServiceKind) -> ConcreteAction {
    match kind {
        ServiceKind::Relay => ConcreteAction::DeployRelayService,
        ServiceKind::Nas => ConcreteAction::DeployNasService,
        ServiceKind::Llm => ConcreteAction::DeployLlmService,
    }
}

/// Map a sibling-service kind to its undeploy action.
fn undeploy_action_for(kind: ServiceKind) -> ConcreteAction {
    match kind {
        ServiceKind::Relay => ConcreteAction::UndeployRelayService,
        ServiceKind::Nas => ConcreteAction::UndeployNasService,
        ServiceKind::Llm => ConcreteAction::UndeployLlmService,
    }
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
                "unknown role preset {raw:?}. Expected one of: anchor, admin, exit, relay, nas, llm, client, blind_exit"
            ),
            RoleCliError::UnknownCapability { raw } => format!(
                "unknown capability flag {raw:?}. Expected one of: serves_exit, serves_relay, serves_nas, serves_llm, anchor.gossip_seed, anchor.bundle_pull, anchor.enrollment_endpoint, anchor.relay_colocation, anchor.port_mapping_authoritative"
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

/// Reviewed launchd plist that bakes the macOS daemon's primary role
/// into its `--node-role` `ProgramArguments` pair. `role set` rewrites
/// that pair in place on macOS (see
/// [`rewrite_macos_plist_node_role`]). Mirrors
/// `REVIEWED_LAUNCHDAEMON_PLIST` in `rustynetd::macos_service_hardening`.
pub const MACOS_DAEMON_PLIST_PATH: &str = "/Library/LaunchDaemons/com.rustynet.daemon.plist";

/// Per-OS default for the file `role set` rewrites to persist the
/// daemon's primary role across a restart. Mirrors the
/// [`platform_default_role_audit_log_path`] pattern so the CLI lands
/// at the correct target on each OS without operator configuration.
///
/// - Linux: the systemd `EnvironmentFile` (`/etc/default/rustynetd`).
///   `rustynetd.service` substitutes `RUSTYNET_NODE_ROLE` from that
///   file into `--node-role`, so rewriting the file changes the role
///   the daemon reads on the next restart.
/// - Windows: the same env-file convention (`DEFAULT_DAEMON_ENV_PATH`),
///   preserved unchanged.
/// - macOS: launchd does **not** expand `EnvironmentVariables` into
///   `ProgramArguments`, and the daemon resolves its role only from the
///   `--node-role` argv pair (`rustynetd` has no env-var role
///   fallback). The role therefore lives in the launchd plist's
///   `ProgramArguments`; the executor rewrites that pair in place. A
///   plain env-file write (the Linux path) lands at `/etc/default/`,
///   which does not exist on macOS, and even if it did the daemon
///   would never read it.
pub fn platform_default_daemon_env_path() -> &'static str {
    daemon_env_path_for_os(std::env::consts::OS)
}

/// Pure per-OS resolver behind [`platform_default_daemon_env_path`].
/// Split out so every OS branch is unit-testable (the public wrapper
/// only ever evaluates the build-target branch). `std::env::consts::OS`
/// reflects the build target, which on each guest is the OS the role
/// CLI runs on.
fn daemon_env_path_for_os(target_os: &str) -> &'static str {
    match target_os {
        "macos" => MACOS_DAEMON_PLIST_PATH,
        _ => DEFAULT_DAEMON_ENV_PATH,
    }
}

/// OS-appropriate operator instruction for restarting the daemon after
/// a local-only role change so the new primary role takes effect. The
/// live-lab orchestrator restarts the daemon itself; this string is the
/// guidance a human operator follows on each platform.
pub fn daemon_restart_instruction() -> String {
    daemon_restart_instruction_for_os(std::env::consts::OS)
}

/// Pure per-OS resolver behind [`daemon_restart_instruction`], split out
/// so every OS branch is unit-testable.
fn daemon_restart_instruction_for_os(target_os: &str) -> String {
    match target_os {
        // RELOAD (bootout + bootstrap), not `kickstart -k`: kickstart restarts
        // the already-loaded launchd job with its in-memory ProgramArguments
        // and does NOT re-read the plist file, so the rewritten `--node-role`
        // would be ignored and the daemon would come back in its old role.
        "macos" => "Reload the daemon so the new primary role takes effect: `sudo launchctl bootout system/com.rustynet.daemon && sudo launchctl bootstrap system /Library/LaunchDaemons/com.rustynet.daemon.plist`.".to_owned(),
        "windows" => {
            "Restart the daemon so the new primary role takes effect: `Restart-Service rustynetd`."
                .to_owned()
        }
        _ => "Restart the daemon so the new primary role takes effect: `systemctl restart rustynetd.service`.".to_owned(),
    }
}

/// Rewrite the macOS launchd daemon plist so the daemon comes up as
/// `new_role` on its next restart.
///
/// The daemon reads its primary role only from the `--node-role
/// <value>` pair in `ProgramArguments`, so we replace that value in
/// place — and keep the informational `RUSTYNET_NODE_ROLE`
/// `EnvironmentVariables` entry in sync so the install-hardening
/// validator and any plist reader observe the same role. Indentation
/// and every other line are preserved verbatim.
///
/// Pure (no I/O) so the rewrite is unit-testable; the filesystem
/// wrapper that reads, atomically writes, and fail-closes on a missing
/// `--node-role` pair lives next to `update_node_role_env_file` in
/// `main.rs`.
///
/// Returns `(rewritten_xml, node_role_arg_replaced, env_value_replaced)`.
/// `node_role_arg_replaced == false` means the plist had no
/// `--node-role` pair — the caller must treat that as a fail-closed
/// error rather than write a role the daemon will not read.
pub fn rewrite_macos_plist_node_role(plist: &str, new_role: &str) -> (String, bool, bool) {
    let mut out = String::with_capacity(plist.len() + new_role.len());
    // Each flag is armed by the marker line and consumes only the
    // immediately-following line, so an unrelated later `<string>` can
    // never be mistaken for the value.
    let mut expect_node_role_value = false;
    let mut expect_env_value = false;
    let mut arg_replaced = false;
    let mut env_replaced = false;

    for line in plist.split_inclusive('\n') {
        let (content, newline) = match line.strip_suffix('\n') {
            Some(body) => (body, "\n"),
            None => (line, ""),
        };
        let trimmed = content.trim();

        if expect_node_role_value {
            expect_node_role_value = false;
            if let Some(rewritten) = replace_string_tag_value(content, new_role) {
                out.push_str(&rewritten);
                out.push_str(newline);
                arg_replaced = true;
                continue;
            }
            // Malformed plist (no value line follows the flag); fall
            // through, leaving arg_replaced false so the caller errors.
        }
        if expect_env_value {
            expect_env_value = false;
            if let Some(rewritten) = replace_string_tag_value(content, new_role) {
                out.push_str(&rewritten);
                out.push_str(newline);
                env_replaced = true;
                continue;
            }
        }

        if trimmed == "<string>--node-role</string>" {
            expect_node_role_value = true;
        } else if trimmed == "<key>RUSTYNET_NODE_ROLE</key>" {
            expect_env_value = true;
        }

        out.push_str(content);
        out.push_str(newline);
    }

    (out, arg_replaced, env_replaced)
}

/// If `line` contains a `<string>…</string>` tag, return the line with
/// that tag's inner value replaced by `new_value`, preserving all
/// surrounding whitespace and any text outside the tag. Returns `None`
/// when the line has no `<string>` tag.
fn replace_string_tag_value(line: &str, new_value: &str) -> Option<String> {
    const OPEN: &str = "<string>";
    const CLOSE: &str = "</string>";
    let value_start = line.find(OPEN)? + OPEN.len();
    let value_end = line[value_start..].find(CLOSE)? + value_start;
    let mut rewritten =
        String::with_capacity(line.len() - (value_end - value_start) + new_value.len());
    rewritten.push_str(&line[..value_start]);
    rewritten.push_str(new_value);
    rewritten.push_str(&line[value_end..]);
    Some(rewritten)
}

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
                followup_instructions: vec![daemon_restart_instruction()],
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
                    // Track B Step 3 (B1.4): advertise the default
                    // route first so the daemon takes ownership of
                    // exit-serving NAT/forwarding before the platform
                    // preflight runs. This matches the ordering rule
                    // baked into NodeRoleTaxonomy_2026-05-21.md §10:
                    // "Service deploy precedes capability advertisement"
                    // — the membership-signed advertisement is the
                    // earlier signal, the platform preflight is the
                    // follow-up that prepares the host kernel.
                    actions: vec![
                        ConcreteAction::AdvertiseDefaultRoute,
                        ConcreteAction::DeployExitService,
                    ],
                    followup_instructions: vec![
                        "Issue per-client signed assignment bundles naming this node as `--exit-node-id` so peers can select it (`rustynet assignment issue`)."
                            .to_owned(),
                    ],
                },
                (RolePreset::Exit, RolePreset::Admin) => RoleSetPlan::Allowed {
                    from: current,
                    to: target,
                    kind: TransitionKind::SignedMembership,
                    // Reverse ordering: tear down the platform preflight
                    // (sysctl forwarding off, pf anchor flushed, Windows
                    // NetIPInterface disabled) BEFORE retracting the
                    // signed default route. Leaves a tight window where
                    // forwarding is off but advertisement is still
                    // present — peers fail closed via the existing
                    // route retract on the next reconcile.
                    actions: vec![
                        ConcreteAction::UndeployExitService,
                        ConcreteAction::RetractDefaultRoute,
                    ],
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
                    // Exit-capability side-effects mirror the
                    // explicit admin ↔ exit cells: gaining
                    // serves_exit advertises 0.0.0.0/0 then runs the
                    // platform preflight; losing it must tear the
                    // preflight down and retract the route — leaving
                    // exit NAT/forwarding active after the
                    // capability is revoked is a release-blocking
                    // defect (SecurityMinimumBar §6.D control 7).
                    if validator
                        .adds_capabilities
                        .contains(&Capability::ServesExit)
                    {
                        actions.push(ConcreteAction::AdvertiseDefaultRoute);
                        actions.push(ConcreteAction::DeployExitService);
                    }
                    // Deploy new sibling services before undeploying
                    // the old ones; both precede the operator's
                    // signed membership update (deploy-before-
                    // advertise / undeploy-before-revoke).
                    for &kind in validator.service_deploys.iter() {
                        actions.push(deploy_action_for(kind));
                    }
                    for &kind in validator.service_undeploys.iter() {
                        actions.push(undeploy_action_for(kind));
                    }
                    if validator
                        .removes_capabilities
                        .contains(&Capability::ServesExit)
                    {
                        actions.push(ConcreteAction::UndeployExitService);
                        actions.push(ConcreteAction::RetractDefaultRoute);
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
                    if target == RolePreset::Nas {
                        followup_instructions.push(
                            "Your NAS will be up but DEFAULT-DENY: no device can reach it until the membership owner signs a service-access policy. Authorise devices from your admin box."
                                .to_owned(),
                        );
                        followup_instructions.push(
                            "Resource note: point RUSTYNET_NAS_DATA_ROOT (/etc/default/rustynet-nas) at the dedicated data disk before relying on the role."
                                .to_owned(),
                        );
                    }
                    if target == RolePreset::Llm {
                        followup_instructions.push(
                            "Your LLM node will be up but DEFAULT-DENY: no device can use it until you authorise one — run `rustynet llm allow node:<id>` on your admin box and sign the record."
                                .to_owned(),
                        );
                        followup_instructions.push(
                            "Resource note: the inference engine needs a GPU/accelerator (or a tiny CPU model for testing); it must listen on loopback only."
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
        ConcreteAction::DeployExitService => {
            "install+enable rustynet-exit preflight (platform-specific)".to_owned()
        }
        ConcreteAction::UndeployExitService => {
            "disable+remove rustynet-exit preflight (platform-specific)".to_owned()
        }
        ConcreteAction::DeployNasService => "install+enable rustynet-nas.service".to_owned(),
        ConcreteAction::UndeployNasService => "disable+remove rustynet-nas.service".to_owned(),
        ConcreteAction::DeployLlmService => {
            "install+enable rustynet-llm-gateway.service".to_owned()
        }
        ConcreteAction::UndeployLlmService => {
            "disable+remove rustynet-llm-gateway.service".to_owned()
        }
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
    fn admin_to_exit_advertises_default_route_then_deploys_exit_preflight() {
        let plan = plan_concrete_actions(RolePreset::Admin, RolePreset::Exit, false, env_path());
        match plan {
            RoleSetPlan::Allowed { kind, actions, .. } => {
                assert_eq!(kind, TransitionKind::SignedMembership);
                // Track B Step 3 (B1.4): admin → exit now emits the
                // advertise IPC first, followed by the platform-specific
                // exit preflight install. Ordering matters: the
                // signed-membership advertisement is the earlier signal;
                // the preflight just prepares the host kernel.
                assert_eq!(
                    actions,
                    vec![
                        ConcreteAction::AdvertiseDefaultRoute,
                        ConcreteAction::DeployExitService,
                    ]
                );
            }
            other => panic!("expected Allowed SignedMembership, got {other:?}"),
        }
    }

    #[test]
    fn exit_to_admin_undeploys_exit_preflight_then_retracts_default_route() {
        let plan = plan_concrete_actions(RolePreset::Exit, RolePreset::Admin, false, env_path());
        match plan {
            RoleSetPlan::Allowed { kind, actions, .. } => {
                assert_eq!(kind, TransitionKind::SignedMembership);
                // Reverse ordering: tear down the preflight BEFORE
                // retracting the default route so forwarding is off
                // first.
                assert_eq!(
                    actions,
                    vec![
                        ConcreteAction::UndeployExitService,
                        ConcreteAction::RetractDefaultRoute,
                    ]
                );
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

    // ----- Planner: service-hosting presets (D13.a) -----

    #[test]
    fn target_nas_deploys_nas_service() {
        for &from in &[RolePreset::Client, RolePreset::Admin, RolePreset::Exit] {
            let plan = plan_concrete_actions(from, RolePreset::Nas, false, env_path());
            match plan {
                RoleSetPlan::Allowed { actions, .. } => {
                    assert!(
                        actions.contains(&ConcreteAction::DeployNasService),
                        "({from:?} → nas) missing DeployNasService: {actions:?}"
                    );
                    assert!(!actions.contains(&ConcreteAction::DeployRelayService));
                }
                other => panic!("expected nas transition allowed, got {other:?}"),
            }
        }
    }

    #[test]
    fn current_nas_to_admin_undeploys_nas_service() {
        let plan = plan_concrete_actions(RolePreset::Nas, RolePreset::Admin, false, env_path());
        match plan {
            RoleSetPlan::Allowed { actions, .. } => {
                assert!(actions.contains(&ConcreteAction::UndeployNasService));
                assert!(!actions.contains(&ConcreteAction::UndeployRelayService));
            }
            other => panic!("expected nas departure allowed, got {other:?}"),
        }
    }

    #[test]
    fn target_llm_deploys_llm_service() {
        for &from in &[RolePreset::Client, RolePreset::Admin, RolePreset::Exit] {
            let plan = plan_concrete_actions(from, RolePreset::Llm, false, env_path());
            match plan {
                RoleSetPlan::Allowed { actions, .. } => {
                    assert!(
                        actions.contains(&ConcreteAction::DeployLlmService),
                        "({from:?} → llm) missing DeployLlmService: {actions:?}"
                    );
                }
                other => panic!("expected llm transition allowed, got {other:?}"),
            }
        }
    }

    #[test]
    fn current_llm_to_admin_undeploys_llm_service() {
        let plan = plan_concrete_actions(RolePreset::Llm, RolePreset::Admin, false, env_path());
        match plan {
            RoleSetPlan::Allowed { actions, .. } => {
                assert!(actions.contains(&ConcreteAction::UndeployLlmService));
            }
            other => panic!("expected llm departure allowed, got {other:?}"),
        }
    }

    #[test]
    fn relay_to_nas_deploys_nas_and_undeploys_relay_in_order() {
        // Cross-service transition: the deploy of the new sibling
        // precedes the undeploy of the old one, and both precede the
        // operator's signed membership update.
        let plan = plan_concrete_actions(RolePreset::Relay, RolePreset::Nas, false, env_path());
        match plan {
            RoleSetPlan::Allowed { actions, .. } => {
                assert_eq!(
                    actions,
                    vec![
                        ConcreteAction::DeployNasService,
                        ConcreteAction::UndeployRelayService,
                    ]
                );
            }
            other => panic!("expected relay → nas allowed, got {other:?}"),
        }
    }

    #[test]
    fn nas_to_llm_deploys_llm_and_undeploys_nas() {
        let plan = plan_concrete_actions(RolePreset::Nas, RolePreset::Llm, false, env_path());
        match plan {
            RoleSetPlan::Allowed { actions, .. } => {
                assert_eq!(
                    actions,
                    vec![
                        ConcreteAction::DeployLlmService,
                        ConcreteAction::UndeployNasService,
                    ]
                );
            }
            other => panic!("expected nas → llm allowed, got {other:?}"),
        }
    }

    #[test]
    fn exit_to_nas_tears_down_exit_serving_in_order() {
        // Leaving an exit-bearing preset through the generic arm
        // must tear down the exit preflight and retract 0.0.0.0/0 —
        // exit NAT residue after revocation is release-blocking
        // (SecurityMinimumBar §6.D control 7).
        let plan = plan_concrete_actions(RolePreset::Exit, RolePreset::Nas, false, env_path());
        match plan {
            RoleSetPlan::Allowed { actions, .. } => {
                assert_eq!(
                    actions,
                    vec![
                        ConcreteAction::DeployNasService,
                        ConcreteAction::UndeployExitService,
                        ConcreteAction::RetractDefaultRoute,
                    ]
                );
            }
            other => panic!("expected exit → nas allowed, got {other:?}"),
        }
    }

    #[test]
    fn exit_to_relay_tears_down_exit_serving() {
        let plan = plan_concrete_actions(RolePreset::Exit, RolePreset::Relay, false, env_path());
        match plan {
            RoleSetPlan::Allowed { actions, .. } => {
                assert_eq!(
                    actions,
                    vec![
                        ConcreteAction::DeployRelayService,
                        ConcreteAction::UndeployExitService,
                        ConcreteAction::RetractDefaultRoute,
                    ]
                );
            }
            other => panic!("expected exit → relay allowed, got {other:?}"),
        }
    }

    #[test]
    fn relay_to_exit_activates_exit_serving_and_undeploys_relay() {
        let plan = plan_concrete_actions(RolePreset::Relay, RolePreset::Exit, false, env_path());
        match plan {
            RoleSetPlan::Allowed { actions, .. } => {
                assert_eq!(
                    actions,
                    vec![
                        ConcreteAction::AdvertiseDefaultRoute,
                        ConcreteAction::DeployExitService,
                        ConcreteAction::UndeployRelayService,
                    ]
                );
            }
            other => panic!("expected relay → exit allowed, got {other:?}"),
        }
    }

    #[test]
    fn nas_and_llm_to_blind_exit_require_acknowledgement() {
        for &from in &[RolePreset::Nas, RolePreset::Llm] {
            let plan = plan_concrete_actions(from, RolePreset::BlindExit, false, env_path());
            match plan {
                RoleSetPlan::Blocked { error, .. } => {
                    assert!(matches!(
                        error,
                        RoleCliError::BlindExitRequiresExplicitAcknowledgement { .. }
                    ));
                }
                other => {
                    panic!("expected ack-gated block for {from:?} → blind_exit, got {other:?}")
                }
            }
        }
    }

    #[test]
    fn blind_exit_to_nas_and_llm_is_locked() {
        for &to in &[RolePreset::Nas, RolePreset::Llm] {
            let plan = plan_concrete_actions(RolePreset::BlindExit, to, false, env_path());
            match plan {
                RoleSetPlan::Blocked { error, .. } => {
                    assert!(matches!(error, RoleCliError::BlindExitImmutable { .. }));
                }
                other => panic!("expected blind_exit lock for → {to:?}, got {other:?}"),
            }
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
                ) => {
                    actions.as_slice()
                        == [
                            ConcreteAction::AdvertiseDefaultRoute,
                            ConcreteAction::DeployExitService,
                        ]
                }
                (
                    ExpectedPlanShape::Retract,
                    RoleSetPlan::Allowed {
                        kind: TransitionKind::SignedMembership,
                        actions,
                        ..
                    },
                ) => {
                    actions.as_slice()
                        == [
                            ConcreteAction::UndeployExitService,
                            ConcreteAction::RetractDefaultRoute,
                        ]
                }
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

    // ─── Track B Phase 17: per-OS audit-log defaults ──────────────

    #[test]
    fn platform_default_role_audit_log_path_picks_per_os_layout() {
        let path = super::platform_default_role_audit_log_path();
        if cfg!(target_os = "macos") {
            assert_eq!(
                path, "/usr/local/var/rustynet/role_transitions.audit.log",
                "macOS default must mirror the install layout under /usr/local/var/rustynet"
            );
        } else if cfg!(target_os = "windows") {
            assert_eq!(
                path, r"C:\ProgramData\RustyNet\role_transitions.audit.log",
                "windows default must mirror the install layout under C:\\ProgramData\\RustyNet"
            );
        } else {
            assert_eq!(
                path,
                super::DEFAULT_ROLE_AUDIT_LOG_PATH,
                "linux + other unix defaults must match the canonical /var/lib/rustynet path"
            );
        }
    }

    #[test]
    fn platform_default_role_audit_log_path_is_an_absolute_path() {
        let path = super::platform_default_role_audit_log_path();
        if cfg!(target_os = "windows") {
            // Windows: drive-letter root (`C:\`) is the absolute
            // marker. PathBuf::is_absolute mirrors this on
            // Windows targets.
            assert!(
                path.starts_with(r"C:\") || path.starts_with(r"C:/"),
                "windows default must be drive-letter rooted: {path:?}"
            );
        } else {
            assert!(
                path.starts_with('/'),
                "unix default must be slash-rooted: {path:?}"
            );
        }
    }

    #[test]
    fn resolve_audit_log_path_returns_path_under_canonical_root_when_env_unset() {
        // This test does NOT mutate the process env (workspace has
        // `#[forbid(unsafe_code)]` so the std::env::set_var helpers
        // are not usable). It instead asserts the env-unset
        // fallback equals the per-OS default literal — capturing
        // the contract without depending on test ordering or env
        // hygiene.
        let resolved = super::resolve_audit_log_path();
        if std::env::var_os("RUSTYNET_ROLE_AUDIT_LOG_PATH").is_none() {
            assert_eq!(
                resolved,
                std::path::PathBuf::from(super::platform_default_role_audit_log_path()),
                "env-unset fallback must equal the per-OS default for the current build target"
            );
        }
        // If the env was set by an outer harness, just confirm
        // the resolution returned a non-empty PathBuf.
        else {
            assert!(
                !resolved.as_os_str().is_empty(),
                "env-set resolve must return a non-empty path"
            );
        }
    }

    // ----- macOS launchd plist role rewrite -----

    /// Minimal but representative slice of the launchd daemon plist the
    /// install script renders: the `--node-role` ProgramArguments pair
    /// plus the informational `RUSTYNET_NODE_ROLE` env entry, with the
    /// same indentation the real plist uses.
    const SAMPLE_DAEMON_PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/rustynetd</string>
        <string>daemon</string>
        <string>--node-id</string>
        <string>macos-1</string>
        <string>--node-role</string>
        <string>client</string>
        <string>--backend</string>
        <string>macos-wireguard-userspace-shared</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>RUSTYNET_NODE_ROLE</key>
        <string>client</string>
        <key>RUSTYNET_NETWORK_ID</key>
        <string>lab</string>
    </dict>
</dict>
</plist>
"#;

    #[test]
    fn rewrite_macos_plist_node_role_replaces_arg_and_env() {
        let (out, arg_replaced, env_replaced) =
            rewrite_macos_plist_node_role(SAMPLE_DAEMON_PLIST, "admin");
        assert!(
            arg_replaced,
            "expected the --node-role value to be replaced"
        );
        assert!(
            env_replaced,
            "expected the RUSTYNET_NODE_ROLE env value to be replaced"
        );
        // The argv pair now carries admin.
        assert!(
            out.contains("<string>--node-role</string>\n        <string>admin</string>"),
            "rewritten plist must carry --node-role admin: {out}"
        );
        // The env entry is kept in sync.
        assert!(
            out.contains("<key>RUSTYNET_NODE_ROLE</key>\n        <string>admin</string>"),
            "rewritten plist must carry RUSTYNET_NODE_ROLE=admin: {out}"
        );
        // No stale `client` role remains anywhere a role appears.
        assert!(
            !out.contains("<string>client</string>"),
            "no stale client role may remain: {out}"
        );
        // Unrelated lines (the network id, backend) are untouched.
        assert!(out.contains("<string>macos-wireguard-userspace-shared</string>"));
        assert!(out.contains("<key>RUSTYNET_NETWORK_ID</key>\n        <string>lab</string>"));
        // Indentation of the rewritten value line is preserved.
        assert!(out.contains("\n        <string>admin</string>"));
    }

    #[test]
    fn rewrite_macos_plist_node_role_is_fail_closed_when_arg_absent() {
        // A plist with no --node-role pair must report the arg as not
        // replaced so the I/O wrapper fails closed.
        let plist = r#"<plist version="1.0">
<dict>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/rustynetd</string>
        <string>daemon</string>
        <string>--backend</string>
        <string>macos-wireguard-userspace-shared</string>
    </array>
</dict>
</plist>
"#;
        let (out, arg_replaced, env_replaced) = rewrite_macos_plist_node_role(plist, "admin");
        assert!(
            !arg_replaced,
            "no --node-role pair means no arg replacement"
        );
        assert!(
            !env_replaced,
            "no RUSTYNET_NODE_ROLE env means no env replacement"
        );
        // Nothing was mutated.
        assert_eq!(out, plist);
    }

    #[test]
    fn rewrite_macos_plist_node_role_only_rewrites_immediate_value_line() {
        // The flag must consume only the line right after the marker,
        // so a later unrelated <string> cannot be mistaken for the
        // role value.
        let (out, arg_replaced, _) =
            rewrite_macos_plist_node_role(SAMPLE_DAEMON_PLIST, "blind_exit");
        assert!(arg_replaced);
        // The --node-id value (`macos-1`, which appears before the
        // --node-role marker) is never touched.
        assert!(out.contains("<string>macos-1</string>"));
        assert!(out.contains("<string>--node-role</string>\n        <string>blind_exit</string>"));
    }

    // ----- per-OS daemon role-persistence target + restart instruction -----

    #[test]
    fn daemon_env_path_is_the_launchd_plist_on_macos_and_env_file_elsewhere() {
        // macOS persists the role in the launchd plist (the daemon reads
        // --node-role from argv; no env-file fallback). Linux/Windows use the
        // env file. Regression guard: a macОS env-file write would land at
        // /etc/default/ which does not exist on the guest.
        assert_eq!(daemon_env_path_for_os("macos"), MACOS_DAEMON_PLIST_PATH);
        assert_eq!(daemon_env_path_for_os("linux"), DEFAULT_DAEMON_ENV_PATH);
        assert_eq!(daemon_env_path_for_os("windows"), DEFAULT_DAEMON_ENV_PATH);
        // The live wrapper resolves a non-empty path for the build target.
        assert!(!platform_default_daemon_env_path().is_empty());
    }

    #[test]
    fn macos_restart_instruction_reloads_the_plist_not_kickstart() {
        // Regression guard for the live-lab finding: `launchctl kickstart -k`
        // restarts the already-loaded job WITHOUT re-reading the edited plist,
        // so the rewritten --node-role is ignored. macOS must RELOAD via
        // bootout + bootstrap.
        let macos = daemon_restart_instruction_for_os("macos");
        assert!(
            macos.contains("launchctl bootout"),
            "macOS must bootout: {macos}"
        );
        assert!(
            macos.contains("launchctl bootstrap"),
            "macOS must bootstrap (reload the plist): {macos}"
        );
        assert!(
            !macos.contains("kickstart"),
            "macOS must NOT kickstart (it does not re-read the plist): {macos}"
        );
        // Other platforms keep their service-manager restart.
        assert!(daemon_restart_instruction_for_os("windows").contains("Restart-Service"));
        assert!(daemon_restart_instruction_for_os("linux").contains("systemctl restart"));
    }
}
