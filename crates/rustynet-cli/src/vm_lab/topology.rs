//! Track B Step 1 (B1.5 + B1.1): cross-platform live-lab topology selection.
//!
//! Lets the operator say "run the lab with Windows as the active exit" (or
//! macOS), without rewriting every per-role flag. Two surfaces:
//!
//! 1. `--topology-profile <path>` — JSON file with the alias for each role:
//!    `{ "exit": "<alias>", "relay": "<alias>"?, "anchor": "<alias>"?,
//!      "blind_exit": "<alias>"? }`. Any subset of keys is allowed; the
//!    parser fails closed on unknown keys to catch typos that would
//!    otherwise silently drop a role assignment.
//!
//! 2. `--exit-platform / --relay-platform / --anchor-platform <linux|macos|windows>`
//!    — convenience selectors that pick the first inventory entry whose
//!    `inventory.platform` matches the requested platform.
//!
//! Default behaviour is unchanged: when neither surface is used the
//! orchestrator continues to elect the inventory's Linux exit-1 alias
//! exactly as today, so existing one-shot runs stay byte-for-byte
//! identical against their `setup_live_lab_profile.env`.
//!
//! Mutual-exclusivity is enforced fail-closed: passing both
//! `--exit-vm` and `--exit-platform`, or asking the topology profile +
//! a platform selector to elect different exit aliases, is rejected
//! before the orchestrator touches any host.

use std::path::Path;

use serde::{Deserialize, Serialize};

use super::{VmGuestPlatform, VmInventoryEntry, VmLabOrchestrateLiveLabConfig};

/// Roles the topology layer is allowed to assign. Mirrors the JSON keys
/// in a `--topology-profile` document. Capability-level fan-out (e.g.
/// which anchor sub-capabilities the chosen alias hosts) lives in
/// membership state, not here — this enum only names the *role slot*.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TopologyRole {
    Exit,
    Relay,
    Anchor,
    BlindExit,
}

impl TopologyRole {
    pub fn as_str(self) -> &'static str {
        match self {
            TopologyRole::Exit => "exit",
            TopologyRole::Relay => "relay",
            TopologyRole::Anchor => "anchor",
            TopologyRole::BlindExit => "blind_exit",
        }
    }
}

/// Operating-system tag the topology layer understands. Restricted to
/// the three platforms that can host an active role in the live lab
/// (Linux, macOS, Windows). Mobile-class guests (iOS, Android) are
/// `client`-only by OS constraint per `NodeRoleTaxonomy_2026-05-21.md`,
/// so the topology selector explicitly refuses them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TopologyPlatform {
    Linux,
    MacOs,
    Windows,
}

impl TopologyPlatform {
    pub fn as_str(self) -> &'static str {
        match self {
            TopologyPlatform::Linux => "linux",
            TopologyPlatform::MacOs => "macos",
            TopologyPlatform::Windows => "windows",
        }
    }

    pub fn parse(raw: &str) -> Result<Self, String> {
        let normalised = raw.trim().to_ascii_lowercase();
        match normalised.as_str() {
            "linux" => Ok(TopologyPlatform::Linux),
            "macos" | "darwin" => Ok(TopologyPlatform::MacOs),
            "windows" => Ok(TopologyPlatform::Windows),
            _ => Err(format!(
                "unsupported platform selector {raw:?}; expected one of: linux, macos, windows"
            )),
        }
    }
}

impl From<TopologyPlatform> for VmGuestPlatform {
    fn from(value: TopologyPlatform) -> Self {
        match value {
            TopologyPlatform::Linux => VmGuestPlatform::Linux,
            TopologyPlatform::MacOs => VmGuestPlatform::Macos,
            TopologyPlatform::Windows => VmGuestPlatform::Windows,
        }
    }
}

impl TryFrom<VmGuestPlatform> for TopologyPlatform {
    type Error = &'static str;

    fn try_from(value: VmGuestPlatform) -> Result<Self, Self::Error> {
        match value {
            VmGuestPlatform::Linux => Ok(TopologyPlatform::Linux),
            VmGuestPlatform::Macos => Ok(TopologyPlatform::MacOs),
            VmGuestPlatform::Windows => Ok(TopologyPlatform::Windows),
            VmGuestPlatform::Ios | VmGuestPlatform::Android => {
                Err("mobile platforms cannot host topology roles")
            }
        }
    }
}

/// Parsed contents of a `--topology-profile <path>` JSON document.
/// Every field is `Option<String>` because a profile may speak to a
/// subset of roles (e.g. set only `exit` for a Windows-as-exit run).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopologyProfile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blind_exit: Option<String>,
}

impl TopologyProfile {
    pub fn is_empty(&self) -> bool {
        self.exit.is_none()
            && self.relay.is_none()
            && self.anchor.is_none()
            && self.blind_exit.is_none()
    }

    pub fn alias_for(&self, role: TopologyRole) -> Option<&str> {
        match role {
            TopologyRole::Exit => self.exit.as_deref(),
            TopologyRole::Relay => self.relay.as_deref(),
            TopologyRole::Anchor => self.anchor.as_deref(),
            TopologyRole::BlindExit => self.blind_exit.as_deref(),
        }
    }
}

/// Parse a `--topology-profile` JSON document. Fails closed on:
/// - unreadable file
/// - invalid JSON
/// - unknown top-level keys (caught via `deny_unknown_fields`)
/// - an empty profile (every field unset) — that would silently fall
///   back to defaults, masking operator intent.
/// - any aliased value that is not a non-empty inventory-alias-shaped
///   identifier (delegated to [`ensure_topology_alias_value`]).
pub fn parse_topology_profile_file(path: &Path) -> Result<TopologyProfile, String> {
    let body = std::fs::read_to_string(path)
        .map_err(|err| format!("read topology profile {} failed: {err}", path.display()))?;
    parse_topology_profile_str(body.as_str()).map_err(|err| {
        format!(
            "topology profile {} failed validation: {err}",
            path.display()
        )
    })
}

/// String-input variant of [`parse_topology_profile_file`] for testing
/// and for callers that already have the JSON in memory.
pub fn parse_topology_profile_str(body: &str) -> Result<TopologyProfile, String> {
    let parsed: TopologyProfile = serde_json::from_str(body)
        .map_err(|err| format!("invalid topology-profile JSON: {err}"))?;
    if parsed.is_empty() {
        return Err(
            "topology profile must set at least one role (exit/relay/anchor/blind_exit)".to_owned(),
        );
    }
    for role in [
        TopologyRole::Exit,
        TopologyRole::Relay,
        TopologyRole::Anchor,
        TopologyRole::BlindExit,
    ] {
        if let Some(alias) = parsed.alias_for(role) {
            ensure_topology_alias_value(role, alias)?;
        }
    }
    Ok(parsed)
}

fn ensure_topology_alias_value(role: TopologyRole, alias: &str) -> Result<(), String> {
    let trimmed = alias.trim();
    if trimmed.is_empty() {
        return Err(format!(
            "topology profile field {:?} cannot be empty",
            role.as_str()
        ));
    }
    if trimmed != alias {
        return Err(format!(
            "topology profile field {:?} value {alias:?} has leading/trailing whitespace",
            role.as_str()
        ));
    }
    if !trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(format!(
            "topology profile field {:?} value {alias:?} must be ASCII alphanumeric plus . _ -",
            role.as_str()
        ));
    }
    Ok(())
}

/// Derive the topology platform for a single inventory entry. Reuses
/// the existing [`VmGuestPlatform::infer`] heuristic so behaviour
/// matches what the orchestrator already writes into the profile env
/// file (`EXIT_PLATFORM=linux` for entries whose explicit
/// `platform` field is absent and whose `os` string starts with
/// "Debian/Linux" today). Mobile guests are reported as
/// [`TopologyPlatform::Linux`] only when the inference defaults to
/// Linux; otherwise [`platform_for_entry`] returns `None`.
pub(crate) fn platform_for_entry(entry: &VmInventoryEntry) -> Option<TopologyPlatform> {
    let utm_name = entry.controller.as_ref().map(controller_utm_name);
    let inferred = VmGuestPlatform::infer(
        entry.platform,
        entry.os.as_deref(),
        entry.alias.as_str(),
        utm_name.as_deref(),
    );
    TopologyPlatform::try_from(inferred).ok()
}

fn controller_utm_name(controller: &super::VmController) -> String {
    match controller {
        super::VmController::LocalUtm { utm_name, .. } => utm_name.clone(),
    }
}

/// Pick the first inventory entry whose platform matches the requested
/// selector. Iteration order matches the inventory file's `entries`
/// array, so operators can reorder entries to influence the pick.
/// Returns `None` when no entry matches; callers translate that into a
/// hard error with role + platform context.
pub(crate) fn select_alias_by_platform(
    inventory: &[VmInventoryEntry],
    platform: TopologyPlatform,
) -> Option<String> {
    inventory
        .iter()
        .find(|entry| platform_for_entry(entry) == Some(platform))
        .map(|entry| entry.alias.clone())
}

/// Single resolved role-to-alias entry produced by [`resolve_topology`].
/// Carries the alias the orchestrator should ultimately drive plus the
/// reason we picked it (for operator-visible audit + tests).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRoleAlias {
    pub role: TopologyRole,
    pub alias: String,
    pub source: TopologySource,
}

/// Where the resolver got its alias choice from. Surfaced in error
/// messages so operators can tell which knob is in play.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopologySource {
    /// Explicit per-role CLI alias (`--exit-vm`, `--client-vm`, ...).
    /// Always wins when present; mixed with a platform selector
    /// produces a fail-closed error.
    ExplicitCliAlias,
    /// Loaded from a `--topology-profile <path>` JSON document.
    TopologyProfile,
    /// Selected from inventory by `--exit-platform / --relay-platform /
    /// --anchor-platform <platform>`.
    PlatformSelector(TopologyPlatform),
}

/// Operator inputs to [`resolve_topology`]. Borrows over `Option<&str>`
/// rather than owning so the existing orchestrator config can pass its
/// own `exit_vm` / `--exit-platform` borrows in unchanged.
pub struct TopologyResolveInputs<'a> {
    pub topology_profile: Option<&'a TopologyProfile>,
    pub exit_vm_explicit: Option<&'a str>,
    pub exit_platform: Option<TopologyPlatform>,
    pub relay_vm_explicit: Option<&'a str>,
    pub relay_platform: Option<TopologyPlatform>,
    pub anchor_vm_explicit: Option<&'a str>,
    pub anchor_platform: Option<TopologyPlatform>,
    pub blind_exit_vm_explicit: Option<&'a str>,
}

/// Per-role resolution outcome. `None` for roles the operator didn't
/// touch — preserves the historical implicit behaviour for unset
/// slots.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TopologyResolution {
    pub exit: Option<ResolvedRoleAlias>,
    pub relay: Option<ResolvedRoleAlias>,
    pub anchor: Option<ResolvedRoleAlias>,
    pub blind_exit: Option<ResolvedRoleAlias>,
}

#[allow(dead_code)] // accessors used by tests + future-track callers
impl TopologyResolution {
    /// Return the resolved alias the orchestrator should write into the
    /// `exit_vm` slot, or `None` to keep today's default (the inventory
    /// default exit alias).
    pub fn exit_alias(&self) -> Option<&str> {
        self.exit.as_ref().map(|r| r.alias.as_str())
    }

    pub fn relay_alias(&self) -> Option<&str> {
        self.relay.as_ref().map(|r| r.alias.as_str())
    }

    pub fn anchor_alias(&self) -> Option<&str> {
        self.anchor.as_ref().map(|r| r.alias.as_str())
    }

    pub fn blind_exit_alias(&self) -> Option<&str> {
        self.blind_exit.as_ref().map(|r| r.alias.as_str())
    }

    /// True when the operator didn't touch any topology knob, meaning
    /// the orchestrator should fall back to today's default Linux-exit
    /// behaviour without writing any per-role override.
    pub fn is_default(&self) -> bool {
        self.exit.is_none()
            && self.relay.is_none()
            && self.anchor.is_none()
            && self.blind_exit.is_none()
    }
}

/// Resolve the operator's topology inputs into a per-role alias map.
///
/// Hard rules:
///
/// - For each role, at most ONE of (explicit CLI alias, topology
///   profile entry, platform selector) may resolve to a value.
///   Combinations error fail-closed — the operator must pick one
///   surface per role.
/// - A platform selector must locate a matching inventory entry; an
///   unmatched selector is a hard error so an operator typing
///   `--exit-platform=windows` against a Linux-only inventory sees
///   the failure immediately rather than silently falling back to the
///   default exit-1.
/// - A topology profile alias must exist in the inventory; the
///   resolver verifies presence so a typo in the profile file fails
///   loudly.
pub(crate) fn resolve_topology(
    inputs: &TopologyResolveInputs<'_>,
    inventory: &[VmInventoryEntry],
) -> Result<TopologyResolution, String> {
    let exit = resolve_one_role(
        TopologyRole::Exit,
        inputs.exit_vm_explicit,
        inputs
            .topology_profile
            .and_then(|p| p.alias_for(TopologyRole::Exit)),
        inputs.exit_platform,
        inventory,
    )?;
    let relay = resolve_one_role(
        TopologyRole::Relay,
        inputs.relay_vm_explicit,
        inputs
            .topology_profile
            .and_then(|p| p.alias_for(TopologyRole::Relay)),
        inputs.relay_platform,
        inventory,
    )?;
    let anchor = resolve_one_role(
        TopologyRole::Anchor,
        inputs.anchor_vm_explicit,
        inputs
            .topology_profile
            .and_then(|p| p.alias_for(TopologyRole::Anchor)),
        inputs.anchor_platform,
        inventory,
    )?;
    let blind_exit = resolve_one_role(
        TopologyRole::BlindExit,
        inputs.blind_exit_vm_explicit,
        inputs
            .topology_profile
            .and_then(|p| p.alias_for(TopologyRole::BlindExit)),
        None,
        inventory,
    )?;
    Ok(TopologyResolution {
        exit,
        relay,
        anchor,
        blind_exit,
    })
}

fn resolve_one_role(
    role: TopologyRole,
    explicit: Option<&str>,
    profile_alias: Option<&str>,
    platform: Option<TopologyPlatform>,
    inventory: &[VmInventoryEntry],
) -> Result<Option<ResolvedRoleAlias>, String> {
    let mut sources = 0usize;
    if explicit.is_some() {
        sources += 1;
    }
    if profile_alias.is_some() {
        sources += 1;
    }
    if platform.is_some() {
        sources += 1;
    }
    if sources > 1 {
        return Err(format!(
            "conflicting topology selectors for role {:?}: pick exactly one of explicit alias / topology profile / platform selector",
            role.as_str()
        ));
    }
    if let Some(alias) = explicit {
        ensure_topology_alias_value(role, alias)?;
        ensure_alias_in_inventory(role, alias, inventory)?;
        return Ok(Some(ResolvedRoleAlias {
            role,
            alias: alias.to_owned(),
            source: TopologySource::ExplicitCliAlias,
        }));
    }
    if let Some(alias) = profile_alias {
        ensure_topology_alias_value(role, alias)?;
        ensure_alias_in_inventory(role, alias, inventory)?;
        return Ok(Some(ResolvedRoleAlias {
            role,
            alias: alias.to_owned(),
            source: TopologySource::TopologyProfile,
        }));
    }
    if let Some(platform) = platform {
        let alias = select_alias_by_platform(inventory, platform).ok_or_else(|| {
            format!(
                "no inventory entry matches platform {:?} for role {:?}",
                platform.as_str(),
                role.as_str()
            )
        })?;
        return Ok(Some(ResolvedRoleAlias {
            role,
            alias,
            source: TopologySource::PlatformSelector(platform),
        }));
    }
    Ok(None)
}

fn ensure_alias_in_inventory(
    role: TopologyRole,
    alias: &str,
    inventory: &[VmInventoryEntry],
) -> Result<(), String> {
    if inventory.iter().any(|entry| entry.alias == alias) {
        Ok(())
    } else {
        Err(format!(
            "topology resolver: alias {alias:?} for role {:?} is not present in the inventory",
            role.as_str()
        ))
    }
}

/// Wrapper for the `vm-lab-orchestrate-live-lab` entry that:
///
/// 1. Loads and parses the optional `--topology-profile` JSON.
/// 2. Parses the optional `--exit/relay/anchor-platform` strings.
/// 3. Runs [`resolve_topology`] against the inventory.
/// 4. Mutates the config so the resolved alias slots into the existing
///    `exit_vm` pipeline. Roles unset by the operator stay at today's
///    implicit defaults, preserving the byte-for-byte Linux-exit
///    behaviour.
///
/// Returns the resolved topology alongside the mutated config so the
/// caller can log + audit the choice and emit `*_PLATFORM` env vars
/// for the bash orchestrator when the resolution differs from the
/// default.
pub(crate) fn apply_topology_overrides_to_orchestrate_config(
    mut config: VmLabOrchestrateLiveLabConfig,
    inventory: &[VmInventoryEntry],
) -> Result<(VmLabOrchestrateLiveLabConfig, TopologyResolution), String> {
    let profile = match config.topology_profile.as_deref() {
        Some(path) => Some(parse_topology_profile_file(path)?),
        None => None,
    };
    let exit_platform =
        parse_optional_platform("--exit-platform", config.exit_platform.as_deref())?;
    let relay_platform =
        parse_optional_platform("--relay-platform", config.relay_platform.as_deref())?;
    let anchor_platform =
        parse_optional_platform("--anchor-platform", config.anchor_platform.as_deref())?;
    let inputs = TopologyResolveInputs {
        topology_profile: profile.as_ref(),
        exit_vm_explicit: config.exit_vm.as_deref(),
        exit_platform,
        relay_vm_explicit: None,
        relay_platform,
        anchor_vm_explicit: None,
        anchor_platform,
        blind_exit_vm_explicit: None,
    };
    let resolution = resolve_topology(&inputs, inventory)?;

    // Topology profile / platform selector may override the exit alias
    // when --exit-vm wasn't set. ExplicitCliAlias is already the
    // operator's value, so we only mutate when the alias came from a
    // profile/platform source.
    if let Some(resolved) = resolution.exit.as_ref()
        && resolved.source != TopologySource::ExplicitCliAlias
    {
        config.exit_vm = Some(resolved.alias.clone());
    }
    Ok((config, resolution))
}

fn parse_optional_platform(
    label: &str,
    raw: Option<&str>,
) -> Result<Option<TopologyPlatform>, String> {
    match raw {
        Some(value) => TopologyPlatform::parse(value)
            .map(Some)
            .map_err(|err| format!("{label}: {err}")),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::{VmGuestPlatform, VmInventoryEntry};

    fn entry_with(alias: &str, platform: Option<VmGuestPlatform>, os: &str) -> VmInventoryEntry {
        VmInventoryEntry {
            alias: alias.to_owned(),
            ssh_target: format!("{alias}.local"),
            ssh_user: Some("test".to_owned()),
            ssh_password: None,
            include_in_all: Some(true),
            os: Some(os.to_owned()),
            last_known_ip: None,
            parent_device: None,
            last_known_network: None,
            network_group: None,
            node_id: None,
            lab_role: None,
            mesh_ip: None,
            exit_capable: Some(false),
            relay_capable: Some(false),
            remote_temp_dir: None,
            utm_staging_dir: None,
            rustynet_src_dir: None,
            platform,
            remote_shell: None,
            guest_exec_mode: None,
            service_manager: None,
            controller: None,
        }
    }

    fn linux(alias: &str) -> VmInventoryEntry {
        entry_with(alias, None, "Debian/Linux")
    }

    fn windows(alias: &str) -> VmInventoryEntry {
        entry_with(alias, Some(VmGuestPlatform::Windows), "Windows 11")
    }

    fn macos(alias: &str) -> VmInventoryEntry {
        entry_with(alias, Some(VmGuestPlatform::Macos), "macOS 26.5 (arm64)")
    }

    #[test]
    fn parse_profile_round_trip() {
        let body = r#"{"exit":"windows-utm-1","relay":"debian-headless-3"}"#;
        let parsed = parse_topology_profile_str(body).expect("parse");
        assert_eq!(parsed.exit.as_deref(), Some("windows-utm-1"));
        assert_eq!(parsed.relay.as_deref(), Some("debian-headless-3"));
        assert!(parsed.anchor.is_none());
        assert!(parsed.blind_exit.is_none());
    }

    #[test]
    fn parse_profile_rejects_unknown_keys_fail_closed() {
        let body = r#"{"exit":"x","unknown":"y"}"#;
        let err = parse_topology_profile_str(body).expect_err("should reject unknown keys");
        assert!(err.contains("unknown field"), "err: {err}");
    }

    #[test]
    fn parse_profile_rejects_empty_document() {
        let err = parse_topology_profile_str("{}").expect_err("empty profile rejected");
        assert!(err.contains("at least one role"));
    }

    #[test]
    fn parse_profile_rejects_invalid_alias_chars() {
        let body = r#"{"exit":"bad alias"}"#;
        let err = parse_topology_profile_str(body).expect_err("rejected");
        assert!(err.contains("ASCII alphanumeric"));
    }

    #[test]
    fn topology_platform_parse_accepts_canonical_strings() {
        assert_eq!(
            TopologyPlatform::parse("linux").unwrap(),
            TopologyPlatform::Linux
        );
        assert_eq!(
            TopologyPlatform::parse("MacOS").unwrap(),
            TopologyPlatform::MacOs
        );
        assert_eq!(
            TopologyPlatform::parse("darwin").unwrap(),
            TopologyPlatform::MacOs
        );
        assert_eq!(
            TopologyPlatform::parse("WINDOWS").unwrap(),
            TopologyPlatform::Windows
        );
    }

    #[test]
    fn topology_platform_parse_rejects_garbage() {
        let err = TopologyPlatform::parse("freebsd").unwrap_err();
        assert!(err.contains("unsupported platform selector"));
    }

    #[test]
    fn platform_for_entry_uses_explicit_field() {
        assert_eq!(
            platform_for_entry(&windows("windows-1")),
            Some(TopologyPlatform::Windows)
        );
        assert_eq!(
            platform_for_entry(&macos("macos-1")),
            Some(TopologyPlatform::MacOs)
        );
        assert_eq!(
            platform_for_entry(&linux("debian-1")),
            Some(TopologyPlatform::Linux)
        );
    }

    #[test]
    fn select_alias_by_platform_returns_first_match() {
        let inv = vec![linux("debian-1"), windows("win-a"), windows("win-b")];
        assert_eq!(
            select_alias_by_platform(&inv, TopologyPlatform::Windows),
            Some("win-a".to_owned())
        );
        assert_eq!(
            select_alias_by_platform(&inv, TopologyPlatform::Linux),
            Some("debian-1".to_owned())
        );
        assert_eq!(
            select_alias_by_platform(&inv, TopologyPlatform::MacOs),
            None
        );
    }

    #[test]
    fn resolve_topology_default_returns_empty_resolution() {
        let inputs = TopologyResolveInputs {
            topology_profile: None,
            exit_vm_explicit: None,
            exit_platform: None,
            relay_vm_explicit: None,
            relay_platform: None,
            anchor_vm_explicit: None,
            anchor_platform: None,
            blind_exit_vm_explicit: None,
        };
        let inv = vec![linux("debian-1")];
        let resolution = resolve_topology(&inputs, &inv).expect("default resolution");
        assert!(resolution.is_default());
        assert!(resolution.exit_alias().is_none());
    }

    #[test]
    fn resolve_topology_picks_first_inventory_entry_by_platform() {
        let inv = vec![linux("debian-1"), windows("windows-utm-1")];
        let inputs = TopologyResolveInputs {
            topology_profile: None,
            exit_vm_explicit: None,
            exit_platform: Some(TopologyPlatform::Windows),
            relay_vm_explicit: None,
            relay_platform: None,
            anchor_vm_explicit: None,
            anchor_platform: None,
            blind_exit_vm_explicit: None,
        };
        let resolution = resolve_topology(&inputs, &inv).expect("windows exit picked");
        assert_eq!(resolution.exit_alias(), Some("windows-utm-1"));
        assert_eq!(
            resolution.exit.as_ref().unwrap().source,
            TopologySource::PlatformSelector(TopologyPlatform::Windows)
        );
    }

    #[test]
    fn resolve_topology_uses_topology_profile_alias() {
        let inv = vec![linux("debian-1"), windows("windows-utm-1")];
        let profile = TopologyProfile {
            exit: Some("windows-utm-1".to_owned()),
            ..Default::default()
        };
        let inputs = TopologyResolveInputs {
            topology_profile: Some(&profile),
            exit_vm_explicit: None,
            exit_platform: None,
            relay_vm_explicit: None,
            relay_platform: None,
            anchor_vm_explicit: None,
            anchor_platform: None,
            blind_exit_vm_explicit: None,
        };
        let resolution = resolve_topology(&inputs, &inv).expect("profile picks alias");
        assert_eq!(resolution.exit_alias(), Some("windows-utm-1"));
        assert_eq!(
            resolution.exit.as_ref().unwrap().source,
            TopologySource::TopologyProfile
        );
    }

    #[test]
    fn resolve_topology_rejects_conflicting_sources() {
        let inv = vec![linux("debian-1"), windows("windows-utm-1")];
        let profile = TopologyProfile {
            exit: Some("debian-1".to_owned()),
            ..Default::default()
        };
        let inputs = TopologyResolveInputs {
            topology_profile: Some(&profile),
            exit_vm_explicit: None,
            exit_platform: Some(TopologyPlatform::Windows),
            relay_vm_explicit: None,
            relay_platform: None,
            anchor_vm_explicit: None,
            anchor_platform: None,
            blind_exit_vm_explicit: None,
        };
        let err =
            resolve_topology(&inputs, &inv).expect_err("topology + platform conflict rejected");
        assert!(err.contains("conflicting topology selectors"));
    }

    #[test]
    fn resolve_topology_rejects_unknown_alias_in_profile() {
        let inv = vec![linux("debian-1")];
        let profile = TopologyProfile {
            exit: Some("ghost-vm".to_owned()),
            ..Default::default()
        };
        let inputs = TopologyResolveInputs {
            topology_profile: Some(&profile),
            exit_vm_explicit: None,
            exit_platform: None,
            relay_vm_explicit: None,
            relay_platform: None,
            anchor_vm_explicit: None,
            anchor_platform: None,
            blind_exit_vm_explicit: None,
        };
        let err = resolve_topology(&inputs, &inv).expect_err("unknown alias rejected");
        assert!(err.contains("ghost-vm"));
        assert!(err.contains("inventory"));
    }

    #[test]
    fn resolve_topology_rejects_explicit_alias_outside_inventory() {
        let inv = vec![linux("debian-1")];
        let inputs = TopologyResolveInputs {
            topology_profile: None,
            exit_vm_explicit: Some("ghost-vm"),
            exit_platform: None,
            relay_vm_explicit: None,
            relay_platform: None,
            anchor_vm_explicit: None,
            anchor_platform: None,
            blind_exit_vm_explicit: None,
        };
        let err = resolve_topology(&inputs, &inv).expect_err("rejected");
        assert!(err.contains("ghost-vm"));
    }

    #[test]
    fn resolve_topology_rejects_platform_with_no_matching_entry() {
        let inv = vec![linux("debian-1")];
        let inputs = TopologyResolveInputs {
            topology_profile: None,
            exit_vm_explicit: None,
            exit_platform: Some(TopologyPlatform::Windows),
            relay_vm_explicit: None,
            relay_platform: None,
            anchor_vm_explicit: None,
            anchor_platform: None,
            blind_exit_vm_explicit: None,
        };
        let err = resolve_topology(&inputs, &inv).expect_err("no match rejected");
        assert!(err.contains("no inventory entry matches platform"));
    }

    #[test]
    fn resolve_topology_default_linux_exit_remains_implicit() {
        // The byte-for-byte invariant: when no topology knob is set
        // and the operator just passes the existing --exit-vm flag,
        // the resolution surfaces that exit alias with the existing
        // ExplicitCliAlias source, and no per-role overrides leak in
        // for the unset roles.
        let inv = vec![linux("debian-headless-1"), windows("windows-utm-1")];
        let inputs = TopologyResolveInputs {
            topology_profile: None,
            exit_vm_explicit: Some("debian-headless-1"),
            exit_platform: None,
            relay_vm_explicit: None,
            relay_platform: None,
            anchor_vm_explicit: None,
            anchor_platform: None,
            blind_exit_vm_explicit: None,
        };
        let resolution = resolve_topology(&inputs, &inv).expect("ok");
        assert_eq!(resolution.exit_alias(), Some("debian-headless-1"));
        assert_eq!(
            resolution.exit.as_ref().unwrap().source,
            TopologySource::ExplicitCliAlias
        );
        assert!(resolution.relay.is_none());
        assert!(resolution.anchor.is_none());
        assert!(resolution.blind_exit.is_none());
        // Used by Step 1's "byte-for-byte default" integration test:
        // when ONLY explicit aliases are supplied, the resolver does
        // not change anything the orchestrator would otherwise write.
        let exit_platform_is_linux = platform_for_entry(
            inv.iter()
                .find(|e| e.alias == resolution.exit_alias().unwrap())
                .unwrap(),
        ) == Some(TopologyPlatform::Linux);
        assert!(exit_platform_is_linux);
    }

    // ── apply_topology_overrides_to_orchestrate_config integration ─────────

    fn empty_orchestrate_config() -> VmLabOrchestrateLiveLabConfig {
        use std::path::PathBuf;
        VmLabOrchestrateLiveLabConfig {
            inventory_path: PathBuf::from("/dev/null"),
            profile_path: None,
            profile_output_path: None,
            exit_vm: None,
            client_vm: None,
            entry_vm: None,
            aux_vm: None,
            extra_vm: None,
            fifth_client_vm: None,
            ssh_identity_file: PathBuf::from("/dev/null"),
            known_hosts_path: None,
            require_same_network: false,
            script_path: PathBuf::from("/dev/null"),
            report_dir: PathBuf::from("/dev/null"),
            source_mode: None,
            repo_ref: None,
            rebuild_nodes: None,
            max_parallel_node_workers: None,
            skip_gates: false,
            skip_soak: false,
            skip_cross_network: false,
            utm_documents_root: None,
            utmctl_path: None,
            ssh_port: 22,
            discovery_timeout_secs: 5,
            ready_timeout_secs: 300,
            timeout_secs: 86_400,
            collect_artifacts_on_failure: false,
            skip_diagnose_on_failure: false,
            stop_after_ready: false,
            dry_run: false,
            windows_vm: None,
            macos_vm: None,
            windows_only: false,
            validate_linux_daemon_state: false,
            node_assignments: Vec::new(),
            legacy_bash_orchestrator: false,
            orchestrate_ssh_allow_cidrs: None,
            no_fail_on_authenticode: false,
            topology_profile: None,
            exit_platform: None,
            relay_platform: None,
            anchor_platform: None,
        }
    }

    #[test]
    fn apply_overrides_no_topology_knobs_preserves_exit_vm() {
        let inv = vec![linux("debian-headless-1")];
        let mut cfg = empty_orchestrate_config();
        cfg.exit_vm = Some("debian-headless-1".to_owned());
        let cfg_before = cfg.clone();
        let (cfg_after, resolution) =
            apply_topology_overrides_to_orchestrate_config(cfg, &inv).expect("ok");
        // Byte-for-byte: when only --exit-vm is set, the override
        // leaves exit_vm untouched. ExplicitCliAlias source means the
        // resolver agreed with the operator and didn't mutate.
        assert_eq!(cfg_after.exit_vm, cfg_before.exit_vm);
        assert_eq!(cfg_after.topology_profile, cfg_before.topology_profile);
        assert_eq!(cfg_after.exit_platform, cfg_before.exit_platform);
        assert_eq!(
            resolution.exit.as_ref().unwrap().source,
            TopologySource::ExplicitCliAlias
        );
    }

    #[test]
    fn apply_overrides_with_exit_platform_promotes_exit_alias() {
        let inv = vec![linux("debian-headless-1"), windows("windows-utm-1")];
        let mut cfg = empty_orchestrate_config();
        // No --exit-vm; operator only passes --exit-platform=windows.
        cfg.exit_platform = Some("windows".to_owned());
        let (cfg_after, resolution) =
            apply_topology_overrides_to_orchestrate_config(cfg, &inv).expect("ok");
        assert_eq!(cfg_after.exit_vm.as_deref(), Some("windows-utm-1"));
        assert_eq!(
            resolution.exit.as_ref().unwrap().source,
            TopologySource::PlatformSelector(TopologyPlatform::Windows)
        );
    }

    #[test]
    fn apply_overrides_rejects_exit_vm_combined_with_exit_platform() {
        let inv = vec![linux("debian-headless-1"), windows("windows-utm-1")];
        let mut cfg = empty_orchestrate_config();
        cfg.exit_vm = Some("debian-headless-1".to_owned());
        cfg.exit_platform = Some("windows".to_owned());
        let err = apply_topology_overrides_to_orchestrate_config(cfg, &inv)
            .expect_err("conflicting selectors must fail");
        assert!(err.contains("conflicting topology selectors"));
    }

    #[test]
    fn apply_overrides_from_topology_profile_file() {
        let inv = vec![linux("debian-headless-1"), windows("windows-utm-1")];
        let dir = std::env::temp_dir().join(format!(
            "rustynet-topology-profile-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let profile_path = dir.join("topology.json");
        std::fs::write(&profile_path, r#"{"exit":"windows-utm-1"}"#).unwrap();
        let mut cfg = empty_orchestrate_config();
        cfg.topology_profile = Some(profile_path.clone());
        let (cfg_after, resolution) =
            apply_topology_overrides_to_orchestrate_config(cfg, &inv).expect("ok");
        assert_eq!(cfg_after.exit_vm.as_deref(), Some("windows-utm-1"));
        assert_eq!(
            resolution.exit.as_ref().unwrap().source,
            TopologySource::TopologyProfile
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_overrides_unknown_platform_string_fails_fast() {
        let inv = vec![linux("debian-1")];
        let mut cfg = empty_orchestrate_config();
        cfg.exit_platform = Some("plan9".to_owned());
        let err = apply_topology_overrides_to_orchestrate_config(cfg, &inv)
            .expect_err("garbage platform must fail");
        assert!(err.contains("unsupported platform selector"));
    }
}
