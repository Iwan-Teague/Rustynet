#![allow(dead_code)]
use std::path::Path;
use std::sync::Arc;

use crate::vm_lab::DaemonProbeOp;
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::{
    AdapterError, BundleKind, InstallReport, MembershipOwnerKey, MembershipSnapshot, NodeId,
    NodeMembershipPeer, TrafficTestResult, TunnelsList, ValidatorReport, WireguardPublicKey,
};
use crate::vm_lab::orchestrator::remote_shell::RemoteShellHost;
use crate::vm_lab::orchestrator::role_validation::identity_challenge::IdentityEvidence;
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

/// Typed role/posture validators whose platform command and evaluator policy
/// are owned behind [`NodeAdapter`]. Stages select intent; adapters select OS
/// paths and validation implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleValidatorKind {
    RuntimeAcls,
    ServiceHardening,
    KeyCustody,
    Authenticode,
    MeshStatus,
    DnsFailclosed,
}

/// SSH connection parameters exposed so orchestrator stages that dispatch
/// standalone e2e validation binaries can construct the correct command line.
/// Not used by general-purpose stages; those go through `RemoteShellHost`.
#[derive(Debug, Clone)]
pub struct SshConnectionParams {
    pub host: String,
    pub port: u16,
    pub user: Option<String>,
    pub identity_file: std::path::PathBuf,
    pub known_hosts: std::path::PathBuf,
}

impl SshConnectionParams {
    pub fn new(
        host: String,
        port: u16,
        user: Option<String>,
        identity_file: std::path::PathBuf,
        known_hosts: std::path::PathBuf,
    ) -> Self {
        SshConnectionParams {
            host: format!("{host}:{port}"),
            port,
            user,
            identity_file,
            known_hosts,
        }
    }
}

/// Per-node, per-OS interface for the orchestration pipeline.
/// Connection details are injected at construction via `NodeConnection`;
/// no transport argument appears in any method signature.
pub trait NodeAdapter: Send + Sync + std::fmt::Debug {
    fn platform(&self) -> VmGuestPlatform;

    /// Return a human-readable OS version string for evidence capture
    /// (e.g. "Linux 6.1.0-26-amd64", "macOS 14.5"). Default implementation
    /// returns the platform name in lowercase.
    fn collect_os_version(&self) -> String {
        format!("{:?}", self.platform()).to_lowercase()
    }

    /// The alias this adapter was constructed for (matches `NodeRoleAssignment::alias`).
    fn alias(&self) -> &str;

    /// SSH connection parameters for stages that dispatch standalone e2e
    /// validation binaries. Returns `None` for non-SSH transports (ADB, MDM).
    fn ssh_connection_params(&self) -> Option<SshConnectionParams> {
        None
    }

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

    /// Gather node-identity evidence for the §4.7 challenge, tagged with its
    /// [`IdentityEvidence::provenance`] so [`adjudicate_identity`] can require a
    /// LIVE daemon self-report. Distinct from [`collect_node_id`], which prefers
    /// a static config artifact for bootstrap-tolerance and so cannot, on
    /// macOS/Windows, prove the running daemon's identity.
    ///
    /// The default fails closed (unsupported) — desktop adapters override it,
    /// and non-desktop platforms are rejected before the challenge runs.
    ///
    /// [`adjudicate_identity`]: crate::vm_lab::orchestrator::role_validation::identity_challenge::adjudicate_identity
    fn collect_live_identity(&self) -> Result<IdentityEvidence, AdapterError> {
        Err(AdapterError::UnsupportedPlatform {
            platform: self.platform(),
            message: "live node-identity challenge is not implemented for this platform".to_owned(),
        })
    }

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
    /// flag. Must be called after `issue_bundles_to_dir` creates the local key,
    /// but before any signed bundle is installed, so verify-before-apply cannot
    /// observe a bundle without its matching verifier.
    fn distribute_verifier_key(
        &self,
        kind: BundleKind,
        pub_key_path: &Path,
    ) -> Result<(), AdapterError>;

    // ── Validators ────────────────────────────────────────────────

    fn run_validator(&self, op: DaemonProbeOp) -> Result<ValidatorReport, AdapterError>;

    /// Run a typed role validator, gated by the §4.7 node-identity challenge.
    ///
    /// `expected_node_id` is the id the orchestrator recorded for this node slot
    /// at CollectPubkeys. Before the validator's own check runs, the dispatch
    /// PROVES (via a live daemon self-report) that the probed connection reaches
    /// that node — so a passing validator cannot be a right-name/wrong-node
    /// false-green. Fail-closed: a missing expected id, a mismatch, or an
    /// un-assertable (non-live) identity all fail the validator.
    fn run_role_validator(
        &self,
        kind: RoleValidatorKind,
        expected_node_id: Option<&str>,
    ) -> Result<(), AdapterError> {
        run_typed_role_validator(self, kind, expected_node_id)
    }

    fn supports_role_validator(&self, _kind: RoleValidatorKind) -> bool {
        matches!(
            self.platform(),
            VmGuestPlatform::Linux | VmGuestPlatform::Macos | VmGuestPlatform::Windows
        )
    }

    // ── Traffic tests ─────────────────────────────────────────────

    /// Positive connectivity: confirm this node reaches `peer_mesh_ip` via tunnel.
    fn ping_mesh_peer(&self, peer_mesh_ip: &str) -> Result<TrafficTestResult, AdapterError>;

    /// Negative ACL test: confirm default-deny blocks traffic to a non-mesh IP.
    /// MUST return `TrafficTestResult::Blocked` for the stage to pass.
    /// `Reachable` result = security failure, stage fails.
    fn probe_denied_peer(&self, denied_ip: &str) -> Result<TrafficTestResult, AdapterError>;

    fn collect_active_tunnels(&self) -> Result<TunnelsList, AdapterError>;

    // ── Active full-tunnel exit serving ───────────────────────────

    /// Activate full-tunnel exit-serving on this (exit) node: instruct the live
    /// daemon to advertise the default route (`0.0.0.0/0`), which makes it apply
    /// IP forwarding + source-NAT for client mesh traffic. This is the operator
    /// "become an exit node" action; the lab's standard flow never sends it, so
    /// the exit only validates its role/posture/mesh, never active NAT egress.
    /// Returns the daemon's own failure reason on rejection (so a host missing
    /// the WinNAT/HNS stack surfaces a clear remediation message, not a bare
    /// error). Default: not applicable to this platform's adapter.
    fn activate_exit_serving(&self) -> Result<(), AdapterError> {
        Err(AdapterError::UnsupportedPlatform {
            platform: self.platform(),
            message:
                "active full-tunnel exit-serving activation is implemented for the Windows and Linux exit adapters"
                    .to_owned(),
        })
    }

    /// Assert this node is ACTIVELY serving as a full-tunnel exit: IP forwarding
    /// enabled on the tunnel + egress interfaces AND a NAT mapping the mesh
    /// present. Distinct from holding the exit role — proves the dataplane
    /// actually NATs client traffic. Default: not applicable to this platform.
    fn assert_exit_actively_serving(&self) -> Result<(), AdapterError> {
        Err(AdapterError::UnsupportedPlatform {
            platform: self.platform(),
            message:
                "active full-tunnel exit-serving assertion is implemented for the Windows and Linux exit adapters"
                    .to_owned(),
        })
    }

    /// From a CLIENT node, drive sustained external (non-mesh) traffic that — when
    /// the client is full-tunnel through the exit — egresses via the exit's NAT.
    /// Runs in the background so the connection window overlaps the exit's NAT
    /// session check. Default: not applicable (only the client platform drives it).
    fn drive_exit_egress_probe(&self) -> Result<(), AdapterError> {
        Err(AdapterError::UnsupportedPlatform {
            platform: self.platform(),
            message: "exit egress probe is implemented only for the Linux client adapter"
                .to_owned(),
        })
    }

    /// On the EXIT node, assert a NAT session translates a mesh-sourced
    /// (`100.64.0.0/10`) client address outbound — direct proof that client
    /// traffic egresses *via this exit's NAT*, the W1/D7 "client mesh traffic
    /// egresses via the exit" evidence. Retries internally for convergence.
    /// Default: not applicable to this platform.
    fn assert_mesh_client_nat_session(&self) -> Result<(), AdapterError> {
        Err(AdapterError::UnsupportedPlatform {
            platform: self.platform(),
            message:
                "mesh-client NAT-session egress assertion is implemented for the Windows and Linux exit adapters"
                    .to_owned(),
        })
    }

    // ── Relay runtime deploy (relay role) ─────────────────────────

    /// Deploy + enable + start the `rustynet-relay` sibling service on this
    /// (relay) node so the downstream `relay_validation` stage has a live relay
    /// to prove. Mirrors the proven bash relay-deploy: derive the relay
    /// verifier key (raw 32 bytes) from the assignment authority public key the
    /// orchestrator already distributed to the node, install it at the unit's
    /// fail-closed-checked path, then install + enable + start the service via
    /// the shared `ops install-systemd-relay` helper. The relay binary itself is
    /// built + installed by the bootstrap script while the network is still open.
    ///
    /// Default: not implemented for this platform's adapter (fail closed). The
    /// `DeployRelayService` stage reports macOS/Windows relay nodes as named
    /// skips, gated on [`NodeRole::is_supported_for_platform`], pending cross-OS
    /// Phase 8 evidence — so this default is reached only via an internal bug,
    /// never on a normally-gated run.
    fn deploy_relay_service(&self) -> Result<(), AdapterError> {
        Err(AdapterError::UnsupportedPlatform {
            platform: self.platform(),
            message:
                "relay runtime deploy is implemented for the Linux relay adapter (macOS/Windows pending cross-OS Phase 8 evidence)"
                    .to_owned(),
        })
    }

    // ── Cross-OS remote shell (role-validation stages) ────────────

    /// Build a cross-OS [`RemoteShellHost`] for this node from its SSH
    /// connection, so role-validation stages (anchor / relay) can drive the
    /// OS-agnostic primitives (read_file / write_file / run_argv /
    /// tcp_send_recv) without re-threading identity / known-hosts through the
    /// call tree. The returned backend dispatches per the adapter's platform.
    /// Default: not available — only the SSH-backed Linux / macOS / Windows
    /// adapters implement it (fail closed otherwise).
    fn shell_host(&self) -> Result<Arc<dyn RemoteShellHost>, AdapterError> {
        Err(AdapterError::UnsupportedPlatform {
            platform: self.platform(),
            message:
                "remote shell host is only available on the SSH-backed Linux/macOS/Windows adapters"
                    .to_owned(),
        })
    }

    // ── Diagnostics + cleanup ─────────────────────────────────────

    /// Collect diagnostic artifacts to `dst`.
    /// Key material MUST be excluded: `*/keys/*`, `*.priv`, `*.pem` paths
    /// must never appear in the archive.
    fn collect_artifacts(&self, dst: &Path) -> Result<(), AdapterError>;

    /// Ensure passwordless sudo / equivalent access is configured on the
    /// target so that subsequent `cleanup_runtime_state`, `install_daemon`,
    /// and runtime operations can manage daemon processes and the network
    /// stack without blocking for a password prompt. The grant is
    /// temporary (cleared on reboot or by the bootstrap's EXIT trap) and
    /// scoped to the lab subnet. Default: no-op (assumes already
    /// configured or not applicable).
    fn prime_remote_access(&self) -> Result<(), AdapterError> {
        Ok(())
    }

    fn cleanup_runtime_state(&self) -> Result<(), AdapterError>;

    /// Best-effort: the daemon's own fail-closed/startup error reason, read from
    /// the guest `rustynetd.log`, so a stage failure surfaces the cause and not
    /// just the symptom. `Ok(None)` when no daemon-side reason is found (the
    /// default, for adapters with no host-side daemon log).
    fn collect_daemon_failure_reason(&self) -> Result<Option<String>, AdapterError> {
        Ok(None)
    }

    /// After cleanup, assert the node carries no leftover RustyNet dataplane
    /// artifacts that would break the next bootstrap (a default-deny killswitch
    /// blocking egress). Fails loudly with "node still dirty: …" so a reset that
    /// did not take is caught at cleanup, not five stages later as a cargo DNS
    /// timeout. Default `Ok(())` for adapters with no host-side killswitch.
    fn assert_node_clean(&self) -> Result<(), AdapterError> {
        Ok(())
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

/// The §4.7 node-identity challenge gate applied before any typed role
/// validator's own check. Extracted from [`run_typed_role_validator`] so the
/// fail-closed adjudication + error mapping is unit-testable directly, without a
/// full mock [`NodeAdapter`]. `evidence` is the result of
/// `adapter.collect_live_identity()`; a gather error propagates (fail-closed),
/// and any adjudication failure maps to a `Protocol` error naming the specific
/// reason (the substituted-node case carries the `node_id mismatch` substring
/// the T5 wrong-node classifier binds to).
fn enforce_identity_challenge(
    evidence: Result<IdentityEvidence, AdapterError>,
    expected_node_id: Option<&str>,
    kind: RoleValidatorKind,
    alias: &str,
) -> Result<(), AdapterError> {
    use crate::vm_lab::orchestrator::role_validation::identity_challenge::adjudicate_identity;
    let evidence = evidence?;
    if let Err(challenge_err) = adjudicate_identity(expected_node_id, &evidence) {
        return Err(AdapterError::Protocol {
            message: format!(
                "§4.7 node-identity challenge rejected {kind:?} on {alias:?}: {challenge_err}"
            ),
        });
    }
    Ok(())
}

fn run_typed_role_validator<T: NodeAdapter + ?Sized>(
    adapter: &T,
    kind: RoleValidatorKind,
    expected_node_id: Option<&str>,
) -> Result<(), AdapterError> {
    use crate::vm_lab::orchestrator::adapter::macos_install::MACOS_RUSTYNETD_PATH;
    use crate::vm_lab::orchestrator::role_validation::{
        authenticode, dns_failclosed, key_custody, mesh_status, runtime_acls, service_hardening,
    };

    const WINDOWS_DAEMON: &str = r"C:\Program Files\RustyNet\rustynetd.exe";
    let platform = adapter.platform();
    if !matches!(
        platform,
        VmGuestPlatform::Linux | VmGuestPlatform::Macos | VmGuestPlatform::Windows
    ) {
        return Err(AdapterError::UnsupportedPlatform {
            platform,
            message: format!("typed role validator {kind:?} is desktop-only"),
        });
    }
    let daemon_path = match platform {
        VmGuestPlatform::Linux => crate::vm_lab::LINUX_RUSTYNETD_PATH,
        VmGuestPlatform::Macos => MACOS_RUSTYNETD_PATH,
        VmGuestPlatform::Windows => WINDOWS_DAEMON,
        _ => unreachable!("desktop platform checked above"),
    };
    let shell = adapter.shell_host()?;
    let alias = adapter.alias();

    // §4.7 node-identity challenge — PROVE this validator exercised the intended
    // node before trusting its verdict. The live daemon self-report over the
    // probed connection must match the id the orchestrator recorded for this
    // slot at CollectPubkeys; a recorded/config-file id is insufficient. This
    // runs before the validator's own check so a right-name/wrong-node
    // false-green (the historical MeshStatus class) fails here first.
    //
    // Fail-closed across every outcome: a missing expected id
    // (`Unverifiable`), a live mismatch (`NodeIdMismatch`), or an
    // un-assertable non-live identity (`NotLiveAssertion` — today only Windows,
    // whose control CLI has no `status` subcommand, a KNOWN deferred §4.7 gap
    // per the acceptance spec) all reject the validator rather than let it earn
    // a green it has not proven.
    enforce_identity_challenge(
        adapter.collect_live_identity(),
        expected_node_id,
        kind,
        alias,
    )?;

    let result = match (kind, platform) {
        (RoleValidatorKind::RuntimeAcls, VmGuestPlatform::Linux) => {
            runtime_acls::validate_linux_runtime_acls(&*shell, daemon_path, alias)
        }
        (RoleValidatorKind::RuntimeAcls, VmGuestPlatform::Macos) => {
            runtime_acls::validate_macos_runtime_acls(&*shell, daemon_path, alias)
        }
        (RoleValidatorKind::RuntimeAcls, VmGuestPlatform::Windows) => {
            runtime_acls::validate_windows_runtime_acls(&*shell, daemon_path, alias)
        }
        (RoleValidatorKind::ServiceHardening, VmGuestPlatform::Linux) => {
            service_hardening::validate_linux_service_hardening(&*shell, daemon_path, alias)
        }
        (RoleValidatorKind::ServiceHardening, VmGuestPlatform::Macos) => {
            service_hardening::validate_macos_service_hardening(&*shell, daemon_path, alias)
        }
        (RoleValidatorKind::ServiceHardening, VmGuestPlatform::Windows) => {
            service_hardening::validate_windows_service_hardening(&*shell, daemon_path, alias)
        }
        (RoleValidatorKind::KeyCustody, VmGuestPlatform::Linux) => {
            key_custody::validate_linux_key_custody(&*shell, daemon_path, alias)
        }
        (RoleValidatorKind::KeyCustody, VmGuestPlatform::Macos) => {
            key_custody::validate_macos_key_custody(&*shell, daemon_path, alias)
        }
        (RoleValidatorKind::KeyCustody, VmGuestPlatform::Windows) => {
            key_custody::validate_windows_key_custody(&*shell, daemon_path, alias)
        }
        (RoleValidatorKind::Authenticode, VmGuestPlatform::Linux) => {
            authenticode::validate_linux_authenticode(&*shell, daemon_path, alias)
        }
        (RoleValidatorKind::Authenticode, VmGuestPlatform::Macos) => {
            authenticode::validate_macos_authenticode(&*shell, daemon_path, alias)
        }
        (RoleValidatorKind::Authenticode, VmGuestPlatform::Windows) => {
            authenticode::validate_windows_authenticode(&*shell, daemon_path, alias)
        }
        (RoleValidatorKind::MeshStatus, VmGuestPlatform::Linux) => {
            mesh_status::validate_linux_mesh_status(&*shell, daemon_path, alias)
        }
        (RoleValidatorKind::MeshStatus, VmGuestPlatform::Macos) => {
            mesh_status::validate_macos_mesh_status(&*shell, daemon_path, alias)
        }
        (RoleValidatorKind::MeshStatus, VmGuestPlatform::Windows) => {
            mesh_status::validate_windows_mesh_status(&*shell, daemon_path, alias)
        }
        (RoleValidatorKind::DnsFailclosed, VmGuestPlatform::Linux) => {
            dns_failclosed::validate_linux_dns_failclosed(&*shell, daemon_path, alias)
        }
        (RoleValidatorKind::DnsFailclosed, VmGuestPlatform::Macos) => {
            dns_failclosed::validate_macos_dns_failclosed(&*shell, daemon_path, alias)
        }
        (RoleValidatorKind::DnsFailclosed, VmGuestPlatform::Windows) => {
            dns_failclosed::validate_windows_dns_failclosed(&*shell, daemon_path, alias)
        }
        (_, _) => unreachable!("desktop platform checked above"),
    };
    result.map_err(|message| AdapterError::Protocol { message })
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

    // ── §4.7 identity-challenge gate (the wiring in run_typed_role_validator) ──

    use super::{RoleValidatorKind, enforce_identity_challenge};
    use crate::vm_lab::orchestrator::error::AdapterError;
    use crate::vm_lab::orchestrator::role_validation::identity_challenge::IdentityEvidence;

    fn protocol_message(err: AdapterError) -> String {
        match err {
            AdapterError::Protocol { message } => message,
            other => panic!("expected Protocol error, got: {other:?}"),
        }
    }

    #[test]
    fn challenge_gate_rejects_substituted_node_with_mismatch_reason() {
        // The live daemon self-reports its OWN id; the orchestrator expected a
        // DIFFERENT (substituted) id → the validator must be rejected here,
        // BEFORE its own check runs (the §3-T5 wrong-node control at the
        // role-validator level, the historical MeshStatus false-green class).
        let err = enforce_identity_challenge(
            Ok(IdentityEvidence::live("real-node")),
            Some("nc-node-substituted-imposter"),
            RoleValidatorKind::MeshStatus,
            "deb-1",
        )
        .expect_err("substituted node must be rejected");
        let msg = protocol_message(err);
        // Binds to the T5 wrong-node classifier substring.
        assert!(msg.contains("node_id mismatch"), "got: {msg}");
        assert!(msg.contains("§4.7"), "got: {msg}");
    }

    #[test]
    fn challenge_gate_fails_closed_when_no_expected_id() {
        let err = enforce_identity_challenge(
            Ok(IdentityEvidence::live("real-node")),
            None,
            RoleValidatorKind::KeyCustody,
            "deb-1",
        )
        .expect_err("missing expected id must fail closed");
        assert!(protocol_message(err).contains("unverifiable"));
    }

    #[test]
    fn challenge_gate_rejects_non_live_config_file_identity() {
        // A matching id read from a config file is not a live assertion (§4.7);
        // the gate must reject rather than let it pass. This is the Windows
        // outcome today (no status subcommand).
        let err = enforce_identity_challenge(
            Ok(IdentityEvidence::config_file("real-node")),
            Some("real-node"),
            RoleValidatorKind::DnsFailclosed,
            "win-1",
        )
        .expect_err("config-file identity must not satisfy a live challenge");
        assert!(protocol_message(err).contains("not a live assertion"));
    }

    #[test]
    fn challenge_gate_propagates_evidence_gather_error_fail_closed() {
        // If the live identity cannot even be gathered, the validator must fail
        // closed — never proceed to its own check on an unproven node.
        let err = enforce_identity_challenge(
            Err(AdapterError::Ssh {
                message: "daemon socket unreachable".to_owned(),
            }),
            Some("real-node"),
            RoleValidatorKind::RuntimeAcls,
            "deb-1",
        )
        .expect_err("gather failure must propagate");
        assert!(matches!(err, AdapterError::Ssh { .. }));
    }

    #[test]
    fn challenge_gate_admits_matching_live_identity() {
        // The positive control: a live self-report matching the expected id
        // passes the gate, so the validator's own check proceeds.
        assert!(
            enforce_identity_challenge(
                Ok(IdentityEvidence::live("real-node")),
                Some("real-node"),
                RoleValidatorKind::ServiceHardening,
                "deb-1",
            )
            .is_ok()
        );
    }
}
