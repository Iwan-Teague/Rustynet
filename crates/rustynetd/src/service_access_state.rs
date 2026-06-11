//! D13 — derivation and atomic materialisation of the per-service
//! access state consumed by the sibling service binaries
//! (`rustynet-nas`, `rustynet-llm-gateway`).
//!
//! Canonical design:
//! `documents/operations/active/NodeRoleTaxonomyExtension_2026-06-11.md`
//! §5 and the D13.b notes in
//! `documents/operations/active/ServiceHostingRolesDeltaPlan_2026-06-11.md`.
//!
//! The service binaries read, per frame, three line-oriented files
//! from their access dir:
//!
//! - `grants.v1` — one authorised peer node-id per line (E2: the
//!   default-deny grant list derived from signed policy).
//! - `peers.v1` — lines `"overlay-ip node-id"` (identity resolution
//!   for the authenticated tunnel source address, derived from the
//!   verified assignment bundle — never from runtime claims).
//! - `scopes.v1` — LLM only, lines
//!   `"node-id models=a,b quota=N rate=N"` (restrictions on a grant,
//!   never a grant source).
//!
//! A missing or unreadable file means deny-all on the binary side,
//! so the daemon writing these files IS the authorisation hand-off:
//! an empty `grants.v1` is exactly as fail-closed as an absent one.
//! Everything here is deterministic; the daemon (`daemon.rs`) owns
//! the seam that decides *when* to materialise (after each
//! successful signed-state apply) and *where* (env-overridable
//! access dirs).

use std::collections::BTreeMap;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use rustynet_control::membership::{MembershipNodeStatus, MembershipState};
use rustynet_policy::{ContextualPolicySet, Decision, MembershipDirectory};

use crate::service_exposure::{ExposedService, evaluate_service_access};

/// File names of the access-state contract shared with the service
/// binaries (`rustynet-nas/src/main.rs`,
/// `rustynet-llm-gateway/src/main.rs`).
pub const ACCESS_GRANTS_FILE: &str = "grants.v1";
pub const ACCESS_PEERS_FILE: &str = "peers.v1";
pub const ACCESS_SCOPES_FILE: &str = "scopes.v1";

/// Deterministic snapshot of the access state for one exposed
/// service on this node, derived purely from signed inputs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServiceAccessSnapshot {
    /// Authorised peer node-ids (sorted, deduplicated, self excluded).
    pub grants: Vec<String>,
    /// `(overlay address, node-id)` identity map entries for active
    /// membership nodes, sorted by node-id.
    pub peers: Vec<(IpAddr, String)>,
    /// Rendered `scopes.v1` lines. Empty for now: admin scope
    /// distribution rides the signed policy bundle later — we render
    /// nothing rather than something wrong, and an absent/empty
    /// scope entry means "unrestricted grant" on the gateway side
    /// (scopes restrict, they never grant).
    pub scopes: Vec<String>,
}

/// Derive the access snapshot for `service` hosted by
/// `self_node_id` from signed state only.
///
/// - `grants`: every ACTIVE membership node (excluding self) whose
///   [`evaluate_service_access`] decision is `Allow`. The policy
///   engine's default-deny covers empty/missing policy, and rules
///   with an empty `contexts` list never match service contexts —
///   so an empty `ContextualPolicySet` derives an empty grant list.
/// - `peers`: the entries of `overlay_addr_of` (node-id → verified
///   overlay address, built by the daemon from the signed assignment
///   bundle) restricted to ACTIVE membership nodes.
/// - `scopes`: empty (see [`ServiceAccessSnapshot::scopes`]).
pub fn derive_service_access_snapshot(
    policy: &ContextualPolicySet,
    membership_directory: &MembershipDirectory,
    membership_state: &MembershipState,
    self_node_id: &str,
    service: ExposedService,
    overlay_addr_of: &BTreeMap<String, IpAddr>,
) -> ServiceAccessSnapshot {
    let mut grants: Vec<String> = membership_state
        .nodes
        .iter()
        .filter(|node| node.status == MembershipNodeStatus::Active)
        .filter(|node| node.node_id != self_node_id)
        .filter(|node| {
            evaluate_service_access(
                policy,
                membership_directory,
                node.node_id.as_str(),
                self_node_id,
                service,
            ) == Decision::Allow
        })
        .map(|node| node.node_id.clone())
        .collect();
    grants.sort();
    grants.dedup();

    let peers: Vec<(IpAddr, String)> = overlay_addr_of
        .iter()
        .filter(|(node_id, _)| {
            membership_state.nodes.iter().any(|node| {
                node.node_id == **node_id && node.status == MembershipNodeStatus::Active
            })
        })
        .map(|(node_id, addr)| (*addr, node_id.clone()))
        .collect();

    ServiceAccessSnapshot {
        grants,
        peers,
        scopes: Vec::new(),
    }
}

fn render_grants(snapshot: &ServiceAccessSnapshot) -> String {
    let mut body = String::new();
    for grant in &snapshot.grants {
        body.push_str(grant);
        body.push('\n');
    }
    body
}

fn render_peers(snapshot: &ServiceAccessSnapshot) -> String {
    let mut body = String::new();
    for (addr, node_id) in &snapshot.peers {
        body.push_str(&format!("{addr} {node_id}\n"));
    }
    body
}

fn render_scopes(snapshot: &ServiceAccessSnapshot) -> String {
    let mut body = String::new();
    for line in &snapshot.scopes {
        body.push_str(line);
        body.push('\n');
    }
    body
}

/// Write the full access state (`grants.v1`, `peers.v1`,
/// `scopes.v1`) atomically: dir created `0700`, each file written
/// via temp + fsync + rename with mode `0600`. An empty snapshot is
/// intentionally still written — empty `grants.v1` is deny-all per
/// the binaries' parsing, which keeps the no-grants state explicit
/// rather than depending on a leftover file from a previous epoch.
///
/// Write order: identity (`peers.v1`) and restrictions (`scopes.v1`)
/// land before authorisation (`grants.v1`), the mirror of the
/// teardown order in [`remove_access_state`]. Any interleaving a
/// crash can produce is deny-or-correct, never wider than the
/// snapshot.
pub fn write_access_state_atomic(
    dir: &Path,
    snapshot: &ServiceAccessSnapshot,
) -> Result<(), String> {
    ensure_private_dir(dir)?;
    write_file_atomic(dir, ACCESS_PEERS_FILE, &render_peers(snapshot))?;
    write_file_atomic(dir, ACCESS_SCOPES_FILE, &render_scopes(snapshot))?;
    write_file_atomic(dir, ACCESS_GRANTS_FILE, &render_grants(snapshot))?;
    Ok(())
}

/// Variant for apply seams that refresh signed membership without a
/// verified assignment bundle in scope (e.g. the IPC membership
/// apply): rewrite `grants.v1` and `scopes.v1` from the fresh signed
/// state — revocation must take effect immediately — but leave the
/// existing `peers.v1` untouched, because the daemon has no
/// *verified* per-node overlay-address source at that seam and must
/// not fake or guess one. The on-disk map still reflects the last
/// verified bundle; the next bundle-bearing apply rewrites it via
/// [`write_access_state_atomic`].
pub fn write_grants_and_scopes_atomic(
    dir: &Path,
    snapshot: &ServiceAccessSnapshot,
) -> Result<(), String> {
    ensure_private_dir(dir)?;
    write_file_atomic(dir, ACCESS_SCOPES_FILE, &render_scopes(snapshot))?;
    write_file_atomic(dir, ACCESS_GRANTS_FILE, &render_grants(snapshot))?;
    Ok(())
}

/// Remove the materialised access state for a service this node no
/// longer serves. Revocation order: `grants.v1` (authorisation) is
/// deleted FIRST so the service is deny-all before identity
/// (`peers.v1`) and restrictions (`scopes.v1`) disappear —
/// teardown-before-revoke at the materialisation layer. Missing
/// files are fine (already-deny); any other removal failure is an
/// error the caller must surface.
pub fn remove_access_state(dir: &Path) -> Result<(), String> {
    remove_file_if_exists(&dir.join(ACCESS_GRANTS_FILE))?;
    remove_file_if_exists(&dir.join(ACCESS_PEERS_FILE))?;
    remove_file_if_exists(&dir.join(ACCESS_SCOPES_FILE))?;
    // Best-effort: drop the dir itself when empty. A non-empty or
    // busy dir is harmless to leave behind — the deny-all state is
    // "grants.v1 absent", which the removals above already enforce.
    let _ = std::fs::remove_dir(dir);
    Ok(())
}

/// Best-effort fail-closed fallback for a failed write: ensure the
/// service is deny-all by deleting `grants.v1`. Used by the daemon
/// when [`write_access_state_atomic`] errors mid-way, so a stale
/// grant list from a previous signed state can never outlive a
/// failed refresh.
pub fn force_deny_all(dir: &Path) -> Result<(), String> {
    remove_file_if_exists(&dir.join(ACCESS_GRANTS_FILE))
}

fn ensure_private_dir(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir)
        .map_err(|err| format!("create access dir {} failed: {err}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|err| {
            format!(
                "set access dir {} permissions to 0700 failed: {err}",
                dir.display()
            )
        })?;
    }
    Ok(())
}

fn write_file_atomic(dir: &Path, file_name: &str, body: &str) -> Result<(), String> {
    let final_path = dir.join(file_name);
    let tmp_path = dir.join(format!(".{file_name}.tmp"));
    // Remove any stale temp left by a previous crash so create_new
    // below cannot fail on it.
    remove_file_if_exists(&tmp_path)?;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&tmp_path)
        .map_err(|err| format!("create {} failed: {err}", tmp_path.display()))?;
    let write_result = file
        .write_all(body.as_bytes())
        .and_then(|()| file.sync_all());
    drop(file);
    if let Err(err) = write_result {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(format!("write {} failed: {err}", tmp_path.display()));
    }
    std::fs::rename(&tmp_path, &final_path).map_err(|err| {
        let _ = std::fs::remove_file(&tmp_path);
        format!(
            "rename {} -> {} failed: {err}",
            tmp_path.display(),
            final_path.display()
        )
    })
}

fn remove_file_if_exists(path: &Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("remove {} failed: {err}", path.display())),
    }
}

/// Resolve the access dir a service binary consumes. Env-overridable
/// (the systemd units in `scripts/systemd/` export the same
/// variables to the binaries, so daemon and binary agree on one
/// path); defaults match the units.
pub fn service_access_dir(service: ExposedService) -> PathBuf {
    let (env_name, default_path) = match service {
        ExposedService::Nas => ("RUSTYNET_NAS_ACCESS_DIR", "/var/lib/rustynet-nas/access"),
        ExposedService::Llm => ("RUSTYNET_LLM_ACCESS_DIR", "/var/lib/rustynet-llm/access"),
    };
    let raw = std::env::var(env_name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default_path.to_owned());
    PathBuf::from(raw)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr};

    use rustynet_control::membership::{
        MEMBERSHIP_SCHEMA_VERSION, MembershipNode, MembershipNodeStatus, MembershipState,
    };
    use rustynet_policy::{
        ContextualPolicyRule, ContextualPolicySet, MembershipDirectory, MembershipStatus, Protocol,
        RuleAction, TrafficContext,
    };

    use super::{
        ACCESS_GRANTS_FILE, ACCESS_PEERS_FILE, ACCESS_SCOPES_FILE, ServiceAccessSnapshot,
        derive_service_access_snapshot, force_deny_all, remove_access_state,
        write_access_state_atomic, write_grants_and_scopes_atomic,
    };
    use crate::service_exposure::ExposedService;

    fn membership_node(node_id: &str, status: MembershipNodeStatus) -> MembershipNode {
        MembershipNode {
            node_id: node_id.to_owned(),
            node_pubkey_hex: "0a".repeat(32),
            owner: "owner@example.local".to_owned(),
            status,
            roles: vec!["tag:servers".to_owned()],
            capabilities: vec![],
            joined_at_unix: 100,
            updated_at_unix: 100,
        }
    }

    fn membership_state(nodes: Vec<MembershipNode>) -> MembershipState {
        MembershipState {
            schema_version: MEMBERSHIP_SCHEMA_VERSION,
            network_id: "net-1".to_owned(),
            epoch: 1,
            nodes,
            approver_set: vec![],
            quorum_threshold: 1,
            metadata_hash: None,
        }
    }

    fn directory_from(state: &MembershipState) -> MembershipDirectory {
        let mut directory = MembershipDirectory::default();
        for node in &state.nodes {
            let status = match node.status {
                MembershipNodeStatus::Active => MembershipStatus::Active,
                _ => MembershipStatus::Revoked,
            };
            directory.set_node_status(node.node_id.clone(), status);
        }
        directory
    }

    fn allow_rule(peer: &str, host: &str, context: TrafficContext) -> ContextualPolicyRule {
        ContextualPolicyRule {
            src: format!("node:{peer}"),
            dst: format!("node:{host}"),
            protocol: Protocol::Tcp,
            action: RuleAction::Allow,
            contexts: vec![context],
        }
    }

    fn overlay_map(entries: &[(&str, [u8; 4])]) -> BTreeMap<String, IpAddr> {
        entries
            .iter()
            .map(|(node_id, octets)| {
                (
                    (*node_id).to_owned(),
                    IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3])),
                )
            })
            .collect()
    }

    #[test]
    fn empty_policy_derives_empty_grants_default_deny() {
        let state = membership_state(vec![
            membership_node("self-nas", MembershipNodeStatus::Active),
            membership_node("peer-a", MembershipNodeStatus::Active),
            membership_node("peer-b", MembershipNodeStatus::Active),
        ]);
        let directory = directory_from(&state);
        let overlay = overlay_map(&[("peer-a", [100, 64, 0, 11]), ("peer-b", [100, 64, 0, 12])]);

        let snapshot = derive_service_access_snapshot(
            &ContextualPolicySet::default(),
            &directory,
            &state,
            "self-nas",
            ExposedService::Nas,
            &overlay,
        );
        assert!(
            snapshot.grants.is_empty(),
            "empty policy must derive an empty (deny-all) grant list"
        );
        // Identity entries are still rendered: identity resolution is
        // not authorisation, and the binaries deny without a grant.
        assert_eq!(snapshot.peers.len(), 2);
        assert!(snapshot.scopes.is_empty());
    }

    #[test]
    fn explicit_allow_rule_grants_exactly_that_peer() {
        let state = membership_state(vec![
            membership_node("self-nas", MembershipNodeStatus::Active),
            membership_node("peer-a", MembershipNodeStatus::Active),
            membership_node("peer-b", MembershipNodeStatus::Active),
        ]);
        let directory = directory_from(&state);
        let policy = ContextualPolicySet {
            rules: vec![allow_rule("peer-a", "self-nas", TrafficContext::NasService)],
        };

        let snapshot = derive_service_access_snapshot(
            &policy,
            &directory,
            &state,
            "self-nas",
            ExposedService::Nas,
            &BTreeMap::new(),
        );
        assert_eq!(snapshot.grants, vec!["peer-a".to_owned()]);

        // The NasService allow must not widen to the LLM service.
        let llm_snapshot = derive_service_access_snapshot(
            &policy,
            &directory,
            &state,
            "self-nas",
            ExposedService::Llm,
            &BTreeMap::new(),
        );
        assert!(llm_snapshot.grants.is_empty());
    }

    #[test]
    fn self_node_is_never_granted_even_when_policy_allows() {
        let state = membership_state(vec![membership_node(
            "self-nas",
            MembershipNodeStatus::Active,
        )]);
        let directory = directory_from(&state);
        let policy = ContextualPolicySet {
            rules: vec![allow_rule(
                "self-nas",
                "self-nas",
                TrafficContext::NasService,
            )],
        };

        let snapshot = derive_service_access_snapshot(
            &policy,
            &directory,
            &state,
            "self-nas",
            ExposedService::Nas,
            &BTreeMap::new(),
        );
        assert!(snapshot.grants.is_empty(), "self is excluded from grants");
    }

    #[test]
    fn revoked_membership_is_excluded_from_grants_and_peers() {
        let state = membership_state(vec![
            membership_node("self-llm", MembershipNodeStatus::Active),
            membership_node("peer-a", MembershipNodeStatus::Active),
            membership_node("peer-revoked", MembershipNodeStatus::Revoked),
            membership_node("peer-quarantined", MembershipNodeStatus::Quarantined),
        ]);
        let directory = directory_from(&state);
        let policy = ContextualPolicySet {
            rules: vec![
                allow_rule("peer-a", "self-llm", TrafficContext::LlmService),
                allow_rule("peer-revoked", "self-llm", TrafficContext::LlmService),
                allow_rule("peer-quarantined", "self-llm", TrafficContext::LlmService),
            ],
        };
        let overlay = overlay_map(&[
            ("peer-a", [100, 64, 0, 11]),
            ("peer-revoked", [100, 64, 0, 12]),
            ("peer-quarantined", [100, 64, 0, 13]),
            ("not-in-membership", [100, 64, 0, 14]),
        ]);

        let snapshot = derive_service_access_snapshot(
            &policy,
            &directory,
            &state,
            "self-llm",
            ExposedService::Llm,
            &overlay,
        );
        assert_eq!(
            snapshot.grants,
            vec!["peer-a".to_owned()],
            "revoked/quarantined nodes must lose their grant"
        );
        assert_eq!(
            snapshot.peers,
            vec![(
                IpAddr::V4(Ipv4Addr::new(100, 64, 0, 11)),
                "peer-a".to_owned()
            )],
            "identity entries only for active membership nodes"
        );
    }

    #[test]
    fn write_access_state_round_trips_with_private_modes() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dir = temp.path().join("access");
        let snapshot = ServiceAccessSnapshot {
            grants: vec!["peer-a".to_owned(), "peer-b".to_owned()],
            peers: vec![
                (
                    IpAddr::V4(Ipv4Addr::new(100, 64, 0, 11)),
                    "peer-a".to_owned(),
                ),
                (
                    IpAddr::V4(Ipv4Addr::new(100, 64, 0, 12)),
                    "peer-b".to_owned(),
                ),
            ],
            scopes: Vec::new(),
        };

        write_access_state_atomic(&dir, &snapshot).expect("write access state");

        let grants = std::fs::read_to_string(dir.join(ACCESS_GRANTS_FILE)).expect("grants");
        assert_eq!(grants, "peer-a\npeer-b\n");
        let peers = std::fs::read_to_string(dir.join(ACCESS_PEERS_FILE)).expect("peers");
        assert_eq!(peers, "100.64.0.11 peer-a\n100.64.0.12 peer-b\n");
        let scopes = std::fs::read_to_string(dir.join(ACCESS_SCOPES_FILE)).expect("scopes");
        assert_eq!(scopes, "", "scopes render empty until the policy bundle");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir_mode = std::fs::metadata(&dir)
                .expect("dir metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dir_mode, 0o700, "access dir must be 0700");
            for file_name in [ACCESS_GRANTS_FILE, ACCESS_PEERS_FILE, ACCESS_SCOPES_FILE] {
                let mode = std::fs::metadata(dir.join(file_name))
                    .expect("file metadata")
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(mode, 0o600, "{file_name} must be 0600");
            }
        }

        // No temp residue.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .expect("read dir")
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "no temp files may remain");

        // Rewriting with an empty snapshot keeps the deny-all state
        // explicit (empty grants.v1, not an absent file).
        write_access_state_atomic(&dir, &ServiceAccessSnapshot::default())
            .expect("rewrite empty snapshot");
        let grants = std::fs::read_to_string(dir.join(ACCESS_GRANTS_FILE)).expect("grants");
        assert_eq!(grants, "", "empty grants.v1 is deny-all");
    }

    #[test]
    fn grants_and_scopes_only_write_leaves_peers_untouched() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dir = temp.path().join("access");
        let full = ServiceAccessSnapshot {
            grants: vec!["peer-a".to_owned()],
            peers: vec![(
                IpAddr::V4(Ipv4Addr::new(100, 64, 0, 11)),
                "peer-a".to_owned(),
            )],
            scopes: Vec::new(),
        };
        write_access_state_atomic(&dir, &full).expect("initial full write");

        // Membership-only refresh: peer-a revoked, no bundle in scope.
        let revoked = ServiceAccessSnapshot::default();
        write_grants_and_scopes_atomic(&dir, &revoked).expect("grants/scopes refresh");

        let grants = std::fs::read_to_string(dir.join(ACCESS_GRANTS_FILE)).expect("grants");
        assert_eq!(grants, "", "revocation must empty the grant list");
        let peers = std::fs::read_to_string(dir.join(ACCESS_PEERS_FILE)).expect("peers");
        assert_eq!(
            peers, "100.64.0.11 peer-a\n",
            "the last verified identity map stays until a bundle-bearing apply"
        );
    }

    #[test]
    fn remove_access_state_clears_all_files() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dir = temp.path().join("access");
        let snapshot = ServiceAccessSnapshot {
            grants: vec!["peer-a".to_owned()],
            peers: vec![(
                IpAddr::V4(Ipv4Addr::new(100, 64, 0, 11)),
                "peer-a".to_owned(),
            )],
            scopes: Vec::new(),
        };
        write_access_state_atomic(&dir, &snapshot).expect("write access state");

        remove_access_state(&dir).expect("remove access state");
        assert!(!dir.join(ACCESS_GRANTS_FILE).exists());
        assert!(!dir.join(ACCESS_PEERS_FILE).exists());
        assert!(!dir.join(ACCESS_SCOPES_FILE).exists());
        assert!(!dir.exists(), "empty access dir is removed too");

        // Idempotent on an already-clean dir.
        remove_access_state(&dir).expect("remove is idempotent");
    }

    #[test]
    fn force_deny_all_removes_only_the_grant_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dir = temp.path().join("access");
        let snapshot = ServiceAccessSnapshot {
            grants: vec!["peer-a".to_owned()],
            peers: vec![(
                IpAddr::V4(Ipv4Addr::new(100, 64, 0, 11)),
                "peer-a".to_owned(),
            )],
            scopes: Vec::new(),
        };
        write_access_state_atomic(&dir, &snapshot).expect("write access state");

        force_deny_all(&dir).expect("force deny-all");
        assert!(
            !dir.join(ACCESS_GRANTS_FILE).exists(),
            "grants.v1 deleted => binaries deny everyone"
        );
        assert!(dir.join(ACCESS_PEERS_FILE).exists());
    }
}
