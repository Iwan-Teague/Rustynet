#![allow(dead_code)]
use std::path::Path;

use crate::vm_lab::DaemonProbeOp;
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::{
    AdapterError, BundleKind, InstallReport, MembershipOwnerKey, MembershipSnapshot, NodeId,
    NodeMembershipPeer, TrafficTestResult, TunnelsList, ValidatorReport, WireguardPublicKey,
};
use crate::vm_lab::orchestrator::source_archive::SourceArchive;

/// Extract the daemon's own failure reason from a tail of its `rustynetd.log`,
/// so a stage failure can report the *cause* (e.g. a fail-closed membership
/// role mismatch) rather than only the downstream symptom (e.g. "WireGuard
/// adapter did not get an IPv4 address within 90s"). Prefers the most recent
/// reconcile fail-closed line; falls back to the most recent error line.
/// Returns `None` when neither marker is present. Result is single-line and
/// length-bounded so it can be safely appended to a stage error string.
pub(crate) fn extract_daemon_failure_reason(log_tail: &str) -> Option<String> {
    const RECONCILE_MARKER: &str = "reconcile fail-closed:";
    let mut reconcile: Option<String> = None;
    let mut error_fallback: Option<String> = None;
    for line in log_tail.lines() {
        let line = line.trim();
        if let Some(idx) = line.find(RECONCILE_MARKER) {
            reconcile = Some(line[idx..].trim().chars().take(400).collect());
        } else if line.contains("[ERROR]") {
            error_fallback = Some(line.chars().take(400).collect());
        }
    }
    reconcile.or(error_fallback)
}

/// The daemon launch flags every platform's bring-up path MUST pass, so the
/// node's runtime identity / role / backend / enforce-mode can never silently
/// drift between platforms. This is the contract behind the N4 failure class: a
/// dropped `--node-role` defaulted the Windows daemon to `admin` and fail-closed
/// a client-enrolled node. Per-platform parity tests assert each platform's
/// daemon-arg construction includes every flag listed here.
pub(crate) const REQUIRED_DAEMON_LAUNCH_FLAGS: &[&str] = &[
    "--backend",
    "--node-id",
    "--node-role",
    "--auto-tunnel-enforce",
];

/// Per-node, per-OS interface for the orchestration pipeline.
/// Connection details are injected at construction via `NodeConnection`;
/// no transport argument appears in any method signature.
pub trait NodeAdapter: Send + Sync + std::fmt::Debug {
    fn platform(&self) -> VmGuestPlatform;

    /// The alias this adapter was constructed for (matches `NodeRoleAssignment::alias`).
    fn alias(&self) -> &str;

    // ── Install lifecycle ─────────────────────────────────────────

    fn install_daemon(
        &self,
        source: &SourceArchive,
        ctx: &OrchestrationContext,
    ) -> Result<InstallReport, AdapterError>;

    fn start_daemon(&self) -> Result<(), AdapterError>;
    fn stop_daemon(&self) -> Result<(), AdapterError>;
    fn restart_daemon(&self) -> Result<(), AdapterError>;
    fn uninstall_daemon(&self) -> Result<(), AdapterError>;

    /// Transition the daemon from its bootstrap state
    /// (`auto_tunnel_enforce=false`) to a fully-enforcing state
    /// (`auto_tunnel_enforce=true`).
    ///
    /// Called by `EnforceBaselineRuntime` after all verifier keys
    /// (assignment, traversal, dns-zone) are in place.  Default
    /// implementation falls through to `start_daemon`; platforms that need
    /// a richer enforce step (e.g. Linux, which must re-run
    /// `ops install-systemd`) override this method.
    fn enforce_runtime(&self, _ctx: &OrchestrationContext) -> Result<(), AdapterError> {
        self.start_daemon()
    }

    // ── Membership owner (exit role only) ─────────────────────────

    fn issue_membership_owner_key(&self) -> Result<MembershipOwnerKey, AdapterError>;

    fn init_membership_snapshot(
        &self,
        owner_key: &MembershipOwnerKey,
        peers: &[NodeMembershipPeer],
    ) -> Result<MembershipSnapshot, AdapterError>;

    // ── Per-node identity + key collection ────────────────────────

    fn collect_wireguard_public_key(&self) -> Result<WireguardPublicKey, AdapterError>;
    fn collect_node_id(&self) -> Result<NodeId, AdapterError>;

    // ── Bundle distribution ───────────────────────────────────────

    fn distribute_signed_bundle(
        &self,
        kind: BundleKind,
        bundle_path: &Path,
    ) -> Result<(), AdapterError>;

    /// Distribute the verifier public-key for `kind` to this node.
    ///
    /// `pub_key_path` is a local file containing the hex-encoded verifier key
    /// (newline-terminated).  The adapter installs it at the platform-canonical
    /// path used by the daemon's `--{assignment,traversal,dns-zone}-verifier-key`
    /// flag.  Must be called after `issue_bundles_to_dir` and before the daemon
    /// starts, so the daemon can verify the freshly-distributed bundles.
    fn distribute_verifier_key(
        &self,
        kind: BundleKind,
        pub_key_path: &Path,
    ) -> Result<(), AdapterError>;

    // ── Validators ────────────────────────────────────────────────

    fn run_validator(&self, op: DaemonProbeOp) -> Result<ValidatorReport, AdapterError>;

    // ── Traffic tests ─────────────────────────────────────────────

    /// Positive connectivity: confirm this node reaches `peer_mesh_ip` via tunnel.
    fn ping_mesh_peer(&self, peer_mesh_ip: &str) -> Result<TrafficTestResult, AdapterError>;

    /// Negative ACL test: confirm default-deny blocks traffic to a non-mesh IP.
    /// MUST return `TrafficTestResult::Blocked` for the stage to pass.
    /// `Reachable` result = security failure, stage fails.
    fn probe_denied_peer(&self, denied_ip: &str) -> Result<TrafficTestResult, AdapterError>;

    fn collect_active_tunnels(&self) -> Result<TunnelsList, AdapterError>;

    // ── Diagnostics + cleanup ─────────────────────────────────────

    /// Collect diagnostic artifacts to `dst`.
    /// Key material MUST be excluded: `*/keys/*`, `*.priv`, `*.pem` paths
    /// must never appear in the archive.
    fn collect_artifacts(&self, dst: &Path) -> Result<(), AdapterError>;

    fn cleanup_runtime_state(&self) -> Result<(), AdapterError>;

    /// Best-effort: the daemon's own fail-closed/startup error reason, read from
    /// the guest `rustynetd.log`, so a stage failure surfaces the cause and not
    /// just the symptom. `Ok(None)` when no daemon-side reason is found (the
    /// default, for adapters with no host-side daemon log).
    fn collect_daemon_failure_reason(&self) -> Result<Option<String>, AdapterError> {
        Ok(None)
    }

    // ── SSH reachability probe ────────────────────────────────────

    fn check_ssh_reachable(&self) -> Result<(), AdapterError>;

    // ── Endpoint identity ─────────────────────────────────────────

    /// Return the WireGuard-reachable endpoint for this node: "host:51820".
    fn endpoint(&self) -> String;

    // ── Mesh IP collection ────────────────────────────────────────

    fn collect_mesh_ip(&self) -> Result<String, AdapterError>;

    // ── Bundle issuance (exit node only) ──────────────────────────

    fn issue_bundles_to_dir(
        &self,
        kind: BundleKind,
        env_content: &str,
        local_out_dir: &Path,
    ) -> Result<(), AdapterError>;
}

#[cfg(test)]
mod tests {
    use super::extract_daemon_failure_reason;

    #[test]
    fn extract_reason_prefers_reconcile_fail_closed_line() {
        let log = "1780341076 [INFO] rustynetd::daemon: entering reconcile loop\n\
             1780341077 [WARN] rustynetd::daemon: rustynetd reconcile fail-closed: membership reconcile failed: membership role mismatch: local node_role admin requires signed membership capability anchor\n";
        let reason = extract_daemon_failure_reason(log).expect("reason");
        assert!(reason.starts_with("reconcile fail-closed:"));
        assert!(reason.contains("node_role admin requires signed membership capability anchor"));
    }

    #[test]
    fn extract_reason_returns_last_reconcile_line() {
        let log = "[WARN] rustynetd reconcile fail-closed: trust reconcile failed: stale\n\
             [WARN] rustynetd reconcile fail-closed: membership reconcile failed: role mismatch\n";
        let reason = extract_daemon_failure_reason(log).expect("reason");
        assert!(reason.contains("membership reconcile failed: role mismatch"));
        assert!(!reason.contains("trust reconcile failed"));
    }

    #[test]
    fn extract_reason_falls_back_to_error_line() {
        let log = "[INFO] starting\n[ERROR] rustynetd: dns resolver bind failed: address in use\n[INFO] x\n";
        let reason = extract_daemon_failure_reason(log).expect("reason");
        assert!(reason.contains("[ERROR]"));
        assert!(reason.contains("dns resolver bind failed"));
    }

    #[test]
    fn extract_reason_none_when_no_markers() {
        let log = "[INFO] entering reconcile loop\n[INFO] all good\n";
        assert!(extract_daemon_failure_reason(log).is_none());
    }
}
