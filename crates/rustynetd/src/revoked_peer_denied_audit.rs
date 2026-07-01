#![allow(clippy::result_large_err)]

//! Adversarial self-audit proving DD-03/RSA-0007's fix actually works: the
//! dataplane exit-node and LAN-route ACL gates must deny a peer that is
//! REVOKED in signed membership even when it still matches a broad/wildcard
//! ACL allow rule — end-to-end through the real `Phase10Controller` call
//! sites named in the finding, not just the underlying policy evaluator in
//! isolation.
//!
//! Companion of the orchestrator-side `evaluate_revoked_peer_denied_report`
//! in `crates/rustynet-cli/src/vm_lab/mod.rs`, wired as
//! `rustynetd revoked-peer-denied-audit`.
//!
//! ## What this proves
//!
//! `SecurityMinimumBar.md` §3.6/§3.8 (default-deny, one hardened path) —
//! `Phase10Controller::set_exit_node` and `ensure_lan_route_allowed` used to
//! gate ACL decisions through the membership-BLIND
//! [`rustynet_policy::ContextualPolicySet::evaluate`], so a peer named by a
//! stale or wildcard allow rule kept dataplane access even after being
//! revoked in signed membership (DD-03/RSA-0007/0008). The fix routes both
//! call sites through `evaluate_with_membership` instead, matching the
//! pattern the daemon's own trust gates already used.
//!
//! This audit drives the REAL shipped `Phase10Controller`, in-process, with a
//! synthetic backend/system and a deliberately broad allow rule (matches any
//! destination) — no live network, no production state touched:
//!   - a REVOKED peer hitting `set_exit_node` / `ensure_lan_route_allowed`
//!     MUST be denied despite the broad allow rule (the regression this
//!     exists to catch);
//!   - the SAME scenario with an ACTIVE (non-revoked) peer MUST be allowed —
//!     proving this audit isn't vacuously "always deny" and that the
//!     membership-aware gate isn't over-broad.
//!
//! It FAILs LOUD (non-zero exit) if a revoked peer is ever granted access or
//! an active peer is ever wrongly denied.

use rustynet_backend_api::{
    BackendCapabilities, BackendError, ExitMode, NodeId, PeerConfig, Route, RouteKind,
    RuntimeContext, SocketEndpoint, TunnelBackend, TunnelStats,
};
use rustynet_policy::{
    ContextualPolicyRule, ContextualPolicySet, MembershipDirectory, MembershipStatus, Protocol,
    RuleAction, TrafficContext,
};
use serde::{Deserialize, Serialize};

use crate::phase10::{
    ApplyOptions, DryRunSystem, Phase10Controller, Phase10Error, RouteGrantRequest, TrustEvidence,
    TrustPolicy,
};

const REVOKED_PEER_DENIED_AUDIT_SCHEMA_VERSION: u32 = 1;
const REQUESTER_NODE_ID: &str = "node-b";
const REQUESTER_SELECTOR: &str = "user:alice";
const EXIT_NODE_ID: &str = "exit-1";
const LAN_CIDR: &str = "192.168.1.0/24";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokedPeerDeniedAuditReport {
    pub schema_version: u32,
    pub overall_ok: bool,
    pub total_cases: u32,
    /// Count of the 2 "must deny" cases (revoked exit node, revoked LAN
    /// requester) that were correctly DENIED.
    pub revoked_denied: u32,
    /// Count of the 2 "must allow" baseline cases (active exit node, active
    /// LAN requester) that were correctly ALLOWED — proves the gate isn't
    /// vacuously deny-everything.
    pub active_allowed: u32,
    pub violations: Vec<RevokedPeerDeniedCaseResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokedPeerDeniedCaseResult {
    pub id: String,
    pub expectation: String,
    pub outcome: String,
    pub reason: String,
    pub passed: bool,
}

/// Minimal always-succeeding [`TunnelBackend`]. The RSA-0007 fix lives
/// entirely in the ACL/policy layer `Phase10Controller` delegates to, not in
/// backend behavior, so this fixture only needs to let `apply_dataplane_generation`
/// and `set_exit_node` complete without a real WireGuard backend.
#[derive(Debug, Default)]
struct NoopBackend {
    peers: std::collections::BTreeMap<NodeId, PeerConfig>,
}

impl TunnelBackend for NoopBackend {
    fn name(&self) -> &'static str {
        "revoked-peer-denied-audit-noop-backend"
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            supports_roaming: true,
            supports_exit_nodes: true,
            supports_exit_client: true,
            supports_exit_serving: true,
            supports_lan_routes: true,
            supports_ipv6: true,
        }
    }

    fn start(&mut self, _context: RuntimeContext) -> Result<(), BackendError> {
        Ok(())
    }

    fn configure_peer(&mut self, peer: PeerConfig) -> Result<(), BackendError> {
        self.peers.insert(peer.node_id.clone(), peer);
        Ok(())
    }

    fn update_peer_endpoint(
        &mut self,
        node_id: &NodeId,
        endpoint: SocketEndpoint,
    ) -> Result<(), BackendError> {
        if let Some(peer) = self.peers.get_mut(node_id) {
            peer.endpoint = endpoint;
        }
        Ok(())
    }

    fn current_peer_endpoint(
        &self,
        node_id: &NodeId,
    ) -> Result<Option<SocketEndpoint>, BackendError> {
        Ok(self.peers.get(node_id).map(|peer| peer.endpoint))
    }

    fn peer_latest_handshake_unix(
        &mut self,
        _node_id: &NodeId,
    ) -> Result<Option<u64>, BackendError> {
        Ok(None)
    }

    fn remove_peer(&mut self, node_id: &NodeId) -> Result<(), BackendError> {
        self.peers.remove(node_id);
        Ok(())
    }

    fn apply_routes(&mut self, _routes: Vec<Route>) -> Result<(), BackendError> {
        Ok(())
    }

    fn set_exit_mode(&mut self, _mode: ExitMode) -> Result<(), BackendError> {
        Ok(())
    }

    fn stats(&self) -> Result<TunnelStats, BackendError> {
        Ok(TunnelStats {
            peer_count: self.peers.len(),
            bytes_tx: 0,
            bytes_rx: 0,
            using_relay_path: false,
        })
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        self.peers.clear();
        Ok(())
    }
}

/// A deliberately broad ACL: allows `user:alice` to reach ANY destination
/// (`dst: "*"`) under `TrafficContext::SharedExit` — this is the "stale
/// wildcard allow rule" shape from the finding. If membership weren't
/// consulted, a revoked node-b would still pass this rule.
fn broad_allow_policy() -> ContextualPolicySet {
    ContextualPolicySet {
        rules: vec![ContextualPolicyRule {
            src: REQUESTER_SELECTOR.to_owned(),
            dst: "*".to_owned(),
            protocol: Protocol::Any,
            action: RuleAction::Allow,
            contexts: vec![TrafficContext::SharedExit],
        }],
    }
}

fn trust_ok() -> TrustEvidence {
    TrustEvidence {
        tls13_valid: true,
        signed_control_valid: true,
        signed_data_age_secs: 20,
        clock_skew_secs: 10,
    }
}

fn sample_peer() -> PeerConfig {
    PeerConfig {
        node_id: NodeId::new(REQUESTER_NODE_ID).expect("node id should parse"),
        endpoint: SocketEndpoint {
            addr: "203.0.113.10".parse().expect("ip should parse"),
            port: 51820,
        },
        public_key: [9; 32],
        allowed_ips: vec!["100.100.20.2/32".to_owned()],
    }
}

fn runtime_context() -> RuntimeContext {
    RuntimeContext {
        local_node: NodeId::new("node-a").expect("node should parse"),
        interface_name: "rustynet0".to_owned(),
        mesh_cidr: "100.64.0.0/10".to_owned(),
        local_cidr: "100.64.0.1/32".to_owned(),
    }
}

/// Builds a `Phase10Controller` past `apply_dataplane_generation`, ready for
/// `set_exit_node`/`ensure_lan_route_allowed` calls — mirrors the setup
/// shared by phase10.rs's own `set_exit_node_denies_revoked_exit_node` /
/// `ensure_lan_route_allowed_denies_revoked_requester` regression tests.
///
/// `Phase10Controller::new` only seeds a usable membership directory under
/// `#[cfg(test)]` (phase10.rs's own unit tests rely on that). This audit
/// binary runs in a real, non-test build on the guest, so it must seed
/// membership explicitly BEFORE provisioning the peer — otherwise
/// `apply_dataplane_generation` itself is denied ("peer not found in
/// membership") before the actual RSA-0007 scenario is ever exercised.
fn started_controller() -> Result<Phase10Controller<NoopBackend, DryRunSystem>, String> {
    let mut controller = Phase10Controller::new(
        NoopBackend::default(),
        DryRunSystem::default(),
        broad_allow_policy(),
        TrustPolicy::default(),
    );
    controller.set_membership(membership_with(
        MembershipStatus::Active,
        MembershipStatus::Active,
    ));
    controller
        .apply_dataplane_generation(
            trust_ok(),
            runtime_context(),
            vec![sample_peer()],
            vec![Route {
                destination_cidr: "0.0.0.0/0".to_owned(),
                via_node: NodeId::new(REQUESTER_NODE_ID).expect("node should parse"),
                kind: RouteKind::ExitNodeDefault,
            }],
            ApplyOptions::default(),
        )
        .map_err(|err| format!("apply_dataplane_generation failed: {err}"))?;
    Ok(controller)
}

fn membership_with(
    requester_status: MembershipStatus,
    exit_status: MembershipStatus,
) -> MembershipDirectory {
    let mut membership = MembershipDirectory::default();
    membership.set_node_status(REQUESTER_NODE_ID, requester_status);
    membership.set_node_status(EXIT_NODE_ID, exit_status);
    membership.set_selector_members(REQUESTER_SELECTOR, [REQUESTER_NODE_ID]);
    membership
}

fn set_exit_node_case(
    id: &str,
    requester_status: MembershipStatus,
    exit_status: MembershipStatus,
    expect_denied: bool,
) -> RevokedPeerDeniedCaseResult {
    let mut controller = match started_controller() {
        Ok(controller) => controller,
        Err(err) => return build_failed_result(id, expect_denied, err),
    };
    controller.set_membership(membership_with(requester_status, exit_status));
    let exit_node = match NodeId::new(EXIT_NODE_ID) {
        Ok(node) => node,
        Err(err) => return build_failed_result(id, expect_denied, err.to_string()),
    };
    let result = controller.set_exit_node(exit_node, REQUESTER_SELECTOR, Protocol::Tcp);
    finish_case(id, expect_denied, result)
}

fn ensure_lan_route_allowed_case(
    id: &str,
    requester_status: MembershipStatus,
    exit_status: MembershipStatus,
    expect_denied: bool,
) -> RevokedPeerDeniedCaseResult {
    let mut controller = match started_controller() {
        Ok(controller) => controller,
        Err(err) => return build_failed_result(id, expect_denied, err),
    };
    // Grant exit selection with an ACTIVE membership first, so only the LAN
    // route gate itself is under test once membership is (re)set below —
    // mirrors ensure_lan_route_allowed_denies_revoked_requester's setup.
    let exit_node = match NodeId::new(EXIT_NODE_ID) {
        Ok(node) => node,
        Err(err) => return build_failed_result(id, expect_denied, err.to_string()),
    };
    controller.set_membership(membership_with(
        MembershipStatus::Active,
        MembershipStatus::Active,
    ));
    if let Err(err) = controller.set_exit_node(exit_node.clone(), REQUESTER_SELECTOR, Protocol::Tcp)
    {
        return build_failed_result(
            id,
            expect_denied,
            format!("prerequisite set_exit_node failed: {err}"),
        );
    }
    controller.set_lan_access(true);
    controller.advertise_lan_route(exit_node, LAN_CIDR);
    controller.set_lan_route_acl(REQUESTER_SELECTOR, LAN_CIDR, true);

    controller.set_membership(membership_with(requester_status, exit_status));
    let result = controller.ensure_lan_route_allowed(RouteGrantRequest {
        user: REQUESTER_SELECTOR.to_owned(),
        cidr: LAN_CIDR.to_owned(),
        protocol: Protocol::Tcp,
        context: TrafficContext::SharedExit,
    });
    finish_case(id, expect_denied, result)
}

fn finish_case(
    id: &str,
    expect_denied: bool,
    result: Result<(), Phase10Error>,
) -> RevokedPeerDeniedCaseResult {
    let (outcome, reason, denied) = match result {
        Ok(()) => (
            "allowed".to_owned(),
            "ACCEPTED: request was allowed".to_owned(),
            false,
        ),
        Err(err) => {
            let denied = matches!(err, Phase10Error::PolicyDenied);
            ("denied".to_owned(), err.to_string(), denied)
        }
    };
    RevokedPeerDeniedCaseResult {
        id: id.to_owned(),
        expectation: if expect_denied { "deny" } else { "allow" }.to_owned(),
        outcome,
        reason,
        passed: denied == expect_denied,
    }
}

fn build_failed_result(
    id: &str,
    expect_denied: bool,
    reason: String,
) -> RevokedPeerDeniedCaseResult {
    RevokedPeerDeniedCaseResult {
        id: id.to_owned(),
        expectation: if expect_denied { "deny" } else { "allow" }.to_owned(),
        outcome: "build_failed".to_owned(),
        reason,
        passed: false,
    }
}

pub fn run_revoked_peer_denied_audit() -> Result<RevokedPeerDeniedAuditReport, String> {
    let results = [
        set_exit_node_case(
            "set_exit_node_denies_revoked_exit_node",
            MembershipStatus::Active,
            MembershipStatus::Revoked,
            true,
        ),
        set_exit_node_case(
            "set_exit_node_allows_active_exit_node",
            MembershipStatus::Active,
            MembershipStatus::Active,
            false,
        ),
        ensure_lan_route_allowed_case(
            "ensure_lan_route_allowed_denies_revoked_requester",
            MembershipStatus::Revoked,
            MembershipStatus::Active,
            true,
        ),
        ensure_lan_route_allowed_case(
            "ensure_lan_route_allowed_allows_active_requester",
            MembershipStatus::Active,
            MembershipStatus::Active,
            false,
        ),
    ];

    let revoked_denied = results
        .iter()
        .filter(|r| r.expectation == "deny" && r.passed)
        .count() as u32;
    let active_allowed = results
        .iter()
        .filter(|r| r.expectation == "allow" && r.passed)
        .count() as u32;
    let violations: Vec<RevokedPeerDeniedCaseResult> =
        results.iter().filter(|r| !r.passed).cloned().collect();

    Ok(RevokedPeerDeniedAuditReport {
        schema_version: REVOKED_PEER_DENIED_AUDIT_SCHEMA_VERSION,
        overall_ok: violations.is_empty(),
        total_cases: results.len() as u32,
        revoked_denied,
        active_allowed,
        violations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_passes_against_the_real_fixed_controller() {
        let report = run_revoked_peer_denied_audit().expect("audit runs");
        assert!(report.overall_ok, "reviewed funnel must pass: {report:?}");
        assert_eq!(report.total_cases, 4);
        assert_eq!(report.revoked_denied, 2);
        assert_eq!(report.active_allowed, 2);
        assert!(report.violations.is_empty());
    }

    #[test]
    fn revoked_exit_node_is_denied_despite_broad_allow_rule() {
        let result = set_exit_node_case(
            "revoke-case",
            MembershipStatus::Active,
            MembershipStatus::Revoked,
            true,
        );
        assert!(
            result.passed,
            "revoked exit node must be denied: {result:?}"
        );
        assert_eq!(result.outcome, "denied");
    }

    #[test]
    fn revoked_lan_requester_is_denied_despite_broad_allow_rule() {
        let result = ensure_lan_route_allowed_case(
            "revoke-case",
            MembershipStatus::Revoked,
            MembershipStatus::Active,
            true,
        );
        assert!(
            result.passed,
            "revoked LAN requester must be denied: {result:?}"
        );
        assert_eq!(result.outcome, "denied");
    }

    #[test]
    fn active_peer_is_still_allowed_not_vacuously_denied() {
        // Anti-vacuous: if the gate denied everything regardless of
        // membership, this would also report "denied" instead of "allowed".
        let exit_case = set_exit_node_case(
            "active-case",
            MembershipStatus::Active,
            MembershipStatus::Active,
            false,
        );
        assert!(
            exit_case.passed,
            "active exit node must be allowed: {exit_case:?}"
        );
        assert_eq!(exit_case.outcome, "allowed");

        let lan_case = ensure_lan_route_allowed_case(
            "active-case",
            MembershipStatus::Active,
            MembershipStatus::Active,
            false,
        );
        assert!(
            lan_case.passed,
            "active LAN requester must be allowed: {lan_case:?}"
        );
        assert_eq!(lan_case.outcome, "allowed");
    }
}
