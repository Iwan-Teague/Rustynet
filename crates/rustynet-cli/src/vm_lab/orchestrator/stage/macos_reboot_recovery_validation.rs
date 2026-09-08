//! C7: validate the macOS reboot-with-protection survival as a first-class
//! `--node` engine stage (`MacosDnsBackupRebootSurvivalPlan_2026-09-02.md`,
//! Addendum 2026-09-07 follow-up (a)). The stage drives a real
//! `sudo -n shutdown -r now` on the macOS node after capturing pre-reboot
//! evidence that the M1 networksetup-DNS fail-closed protection is in place
//! (durable backup present and mode 0600, every enabled networksetup service
//! pinned to loopback), then waits bounded for SSH to return and the daemon
//! to report LIVE.
//!
//! Mid-recovery seam (follow-up (a)): between "SSH is back + daemon live"
//! and the post-reboot pin probe, the stage redistributes FRESH signed
//! traversal + dns_zone bundles to the rebooted node — through the SAME
//! issue + verifier-key barrier + install path the setup stages use, scoped
//! to the rebooted node — and polls `rustynet status` until the daemon
//! reports a HEALTHY TERMINAL state (allowlisted exactly:
//! `DataplaneApplied` or `ExitActive`, review F1) with a programmed
//! generation. This is load-bearing
//! because the M1 startup guard restores the pre-protection DNS baseline by
//! design: the loopback pins only return when the daemon re-applies its
//! generation, which needs valid (non-expired) signed state. Only then does
//! the stage prove the post-reboot state: the startup-recovery line (or the
//! typed `macos-dns-failclosed-check` reporting clean), overall_ok, every
//! enabled service loopback-pinned again, and the QH-40 shutdown-residue
//! marker ABSENT.
//!
//! FAIL-LOUD: the live result is the stage status. The stage Skips only when
//! the run did not elect macOS for reboot recovery (`--reboot-platform
//! macos`) or when its `validate_baseline_runtime` dependency did not pass;
//! it never reports a dry-run as a pass and never downgrades a failed
//! reboot-recovery proof. A redistribution error, a node stuck in FailClosed,
//! or pins still absent all FAIL the stage — never a skip.

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::stage::distribute_assignments::distribute_bundle_kind_scoped;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};
use crate::vm_lab::orchestrator::{error::BundleKind, remote_shell::RemoteShellHost};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// Post-reboot recovery poll budget: 18 attempts at a 10 s interval bounds
/// the wait at 180 s — comfortably inside the signed-state TTL economics of
/// the freshly redistributed bundles (issued seconds earlier) while still
/// tolerating a slow generation re-apply after a reboot.
const RECOVERY_POLL_MAX_ATTEMPTS: u32 = 18;
/// Interval between `rustynet status` polls of the recovery window.
const RECOVERY_POLL_INTERVAL: Duration = Duration::from_secs(10);
/// Healthy terminal `DataplaneState` tokens the recovery criterion accepts
/// (review F1). The daemon's `state=` field is the Debug render of
/// `DataplaneState` (`crates/rustynetd/src/phase10.rs`), so the criterion is
/// an ALLOWLIST of exactly those two known-healthy terminal states: any
/// other token — `FailClosed`, a renamed/drifted variant family such as
/// `FailClosedDegraded`, or a MISSING `state` field entirely — counts as
/// NOT recovered. A source-pin test below keeps these names tied to the
/// defining enum so a daemon-side rename fails this crate's tests.
const RECOVERED_STATE_DATAPLANE_APPLIED: &str = "DataplaneApplied";
const RECOVERED_STATE_EXIT_ACTIVE: &str = "ExitActive";

pub struct MacosRebootRecoveryValidationStage {
    max_parallel_node_workers: usize,
    shutdown_flag: Arc<std::sync::atomic::AtomicBool>,
}

impl MacosRebootRecoveryValidationStage {
    pub fn new(
        max_parallel_node_workers: usize,
        shutdown_flag: Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Self {
            max_parallel_node_workers: max_parallel_node_workers.max(1),
            shutdown_flag,
        }
    }
}

impl OrchestrationStage for MacosRebootRecoveryValidationStage {
    fn id(&self) -> StageId {
        StageId::MacosRebootRecoveryValidation
    }

    fn name(&self) -> &'static str {
        self.id().as_str()
    }

    fn dependencies(&self) -> &[StageId] {
        // The reboot proof only means something on a node whose daemon was
        // validated live before the reboot, so the baseline runtime
        // validation is the gate: its "skipped: dependency did not pass"
        // record carries the same fail-closed semantics forward.
        &[StageId::ValidateBaselineRuntime]
    }

    fn applies_to_roles(&self) -> &[crate::vm_lab::orchestrator::role::NodeRole] {
        &[]
    }

    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        // Election first: a run that did not elect macOS for reboot recovery
        // (every other run included) records a reported skip, exactly as the
        // sibling C6 role-transition validator does. Only an ELECTED run then
        // fails closed when the topology cannot supply exactly one macOS
        // target.
        if !ctx.macos_reboot_recovery_elected {
            return StageOutcome::Skipped(
                "skipped: macOS is not elected for reboot recovery (reboot_platform != macos)"
                    .to_owned(),
            );
        }
        let alias = match macos_reboot_recovery_alias(ctx) {
            Ok(alias) => alias,
            Err(err) => return StageOutcome::Failed(err),
        };
        let inventory_path = match ctx.inventory_path.as_deref() {
            Some(path) => path.to_owned(),
            None => {
                return StageOutcome::Failed(format!(
                    "{alias}: no inventory path recorded for this run; the macOS live reboot-recovery validator cannot resolve SSH targets"
                ));
            }
        };
        let adapter = match ctx.adapters.get(&alias) {
            Some(adapter) => adapter,
            None => {
                return StageOutcome::Failed(format!(
                    "{alias}: no adapter registered for the macOS reboot-recovery target"
                ));
            }
        };
        let params = match adapter.ssh_connection_params() {
            Some(params) => params,
            None => {
                return StageOutcome::Failed(format!(
                    "{alias}: no SSH connection parameters resolved for the macOS reboot-recovery target"
                ));
            }
        };
        let report_dir = ctx.report_dir.clone();
        let max_parallel_node_workers = self.max_parallel_node_workers;
        let shutdown_flag = Arc::clone(&self.shutdown_flag);
        let recovery_alias = alias.clone();
        let mut recovery_actions = move |node_id: &str| -> Result<(), String> {
            redistribute_fresh_bundles_and_await_generation(
                ctx,
                &recovery_alias,
                node_id,
                max_parallel_node_workers,
                &shutdown_flag,
            )
        };
        match crate::vm_lab::exercise_macos_reboot_recovery_with_recovery_actions(
            &alias,
            Path::new(&inventory_path),
            &params.identity_file,
            Some(params.known_hosts.as_path()),
            Some(report_dir.as_path()),
            &mut recovery_actions,
        ) {
            // `Passed` carries no payload (the sibling C6 validator has the
            // same shape), so the human-readable proof line stays in the
            // helper's Ok value and is intentionally not duplicated here.
            Ok(_) => StageOutcome::Passed,
            Err(err) => StageOutcome::Failed(format!("{alias}: {err}")),
        }
    }
}

/// Mid-recovery action the stage installs on the live helper's seam: give the
/// rebooted node FRESH signed state, then wait for the daemon to apply it.
///
/// Order is contractual (redistribute BEFORE any pin probe): the M1 startup
/// guard restores the pre-protection DNS baseline by design, so the loopback
/// pins only return once the daemon re-applies its generation from valid,
/// non-expired signed state. Traversal first, then dns_zone — the same order
/// the setup stages use.
fn redistribute_fresh_bundles_and_await_generation(
    ctx: &mut OrchestrationContext,
    alias: &str,
    node_id: &str,
    max_parallel_node_workers: usize,
    shutdown_flag: &Arc<std::sync::atomic::AtomicBool>,
) -> Result<(), String> {
    // Review F3: the kind travels IN the tuple — a string-label round trip
    // with a catch-all arm would silently issue a second dns_zone generation
    // on a typo or a future third kind instead of failing to compile.
    const KINDS: [(BundleKind, &str, &str, &str); 2] = [
        (
            BundleKind::Traversal,
            "traversal",
            "rn-traversal",
            "traversal",
        ),
        (BundleKind::DnsZone, "dns_zone", "rn-dns-zone", "dns-zone"),
    ];
    for (kind, label, file_prefix, file_ext) in KINDS {
        match distribute_bundle_kind_scoped(
            ctx,
            kind,
            file_prefix,
            file_ext,
            max_parallel_node_workers,
            shutdown_flag,
            alias,
        ) {
            StageOutcome::Passed => {}
            StageOutcome::Failed(err) => {
                return Err(format!(
                    "fresh {label} bundle redistribution to {alias} (node {node_id}) failed: {err}"
                ));
            }
            unexpected => {
                return Err(format!(
                    "fresh {label} bundle redistribution to {alias} (node {node_id}) returned a non-pass outcome (never allowed mid-recovery): {unexpected:?}"
                ));
            }
        }
    }
    let adapter = ctx.adapters.get(alias).ok_or_else(|| {
        format!("{alias}: no adapter registered for the post-reboot generation poll")
    })?;
    let shell = adapter.shell_host().map_err(|e| {
        format!("{alias}: post-reboot generation poll could not open the adapter shell: {e}")
    })?;
    let platform = adapter.platform();
    let mut sleep = || std::thread::sleep(RECOVERY_POLL_INTERVAL);
    poll_generation_recovery(
        &*shell,
        platform,
        alias,
        node_id,
        RECOVERY_POLL_MAX_ATTEMPTS,
        &mut sleep,
    )
    .map(|status_line| {
        // Keep the proof line in the stage's own log output: the recovery
        // window closed on this exact status observation.
        eprintln!(
            "macos_reboot_recovery: {alias} (node {node_id}) re-applied a programmed generation after fresh bundle redistribution; status: {status_line}"
        );
    })
}

/// One parsed `rustynet status` observation during the recovery window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecoveryStatusObservation {
    /// The daemon's `state=` token — the Debug render of `DataplaneState`
    /// (e.g. `FailClosed` while stuck). A MISSING field stays `None` and the
    /// recovery criterion treats it as not recovered (review F1).
    pub state: Option<String>,
    /// `path_programmed_peer_count=` — peers the daemon has PROGRAMMED from
    /// its applied generation. A missing or unparseable value counts as 0
    /// (fail closed: an unreadable count can never read as recovered).
    pub programmed_peer_count: u32,
    /// `path_live_peer_count=` — carried for the failure message only.
    pub live_peer_count: Option<String>,
}

/// Parse the recovery-relevant fields from a `rustynet status` line
/// (space-separated `key=value` tokens).
pub(crate) fn parse_recovery_status(status_text: &str) -> RecoveryStatusObservation {
    use crate::vm_lab::orchestrator::adapter::ssh::parse_status_field;
    RecoveryStatusObservation {
        state: parse_status_field(status_text, "state"),
        programmed_peer_count: parse_status_field(status_text, "path_programmed_peer_count")
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(0),
        live_peer_count: parse_status_field(status_text, "path_live_peer_count"),
    }
}

/// The recovery criterion (review F1): the daemon reports one of the
/// HEALTHY TERMINAL states — allowlisted exactly, never negated — AND a
/// programmed generation (at least one programmed peer). Both halves are
/// required — a daemon still fail-closed (or in any unknown/drifted state,
/// or reporting no state at all), or one that left FailClosed without
/// applying the fresh bundles, has not recovered.
pub(crate) fn node_has_recovered_generation(observation: &RecoveryStatusObservation) -> bool {
    matches!(
        observation.state.as_deref(),
        Some(RECOVERED_STATE_DATAPLANE_APPLIED) | Some(RECOVERED_STATE_EXIT_ACTIVE)
    ) && observation.programmed_peer_count >= 1
}

/// Poll `rustynet status` through the adapter's remote shell until the
/// daemon reports a healthy terminal state with a programmed generation,
/// bounded to `max_attempts` polls with `between_attempts` invoked between
/// them.
///
/// FAIL CLOSED: on exhaustion the error carries the LAST observation verbatim
/// (the exact status line, or the transport error) — never a silent skip. A
/// failed or erroring status query is a non-recovered attempt and retries
/// within the same window.
pub(crate) fn poll_generation_recovery(
    shell: &dyn RemoteShellHost,
    platform: VmGuestPlatform,
    alias: &str,
    node_id: &str,
    max_attempts: u32,
    between_attempts: &mut dyn FnMut(),
) -> Result<String, String> {
    use crate::vm_lab::orchestrator::role_validation::blind_exit::{
        daemon_socket_path, rustynet_program,
    };
    let socket_env = [("RUSTYNET_DAEMON_SOCKET", daemon_socket_path(platform))];
    let mut last_observation = String::from("no status observation was collected");
    for attempt in 1..=max_attempts {
        let outcome = shell.run_argv(&[rustynet_program(platform), "status"], &socket_env, &[]);
        last_observation = match outcome {
            Ok(status) => {
                let text = String::from_utf8_lossy(&status.stdout);
                let trimmed = text.trim();
                if status.is_success() {
                    let observation = parse_recovery_status(trimmed);
                    if node_has_recovered_generation(&observation) {
                        // `trimmed` cannot be empty here: an empty status
                        // parses to programmed_peer_count=0, which never
                        // satisfies the recovery criterion.
                        return Ok(trimmed.to_owned());
                    }
                    if trimmed.is_empty() {
                        "rustynet status exited 0 with empty output".to_owned()
                    } else {
                        trimmed.to_owned()
                    }
                } else if trimmed.is_empty() {
                    format!("rustynet status exited {}", status.code)
                } else {
                    trimmed.to_owned()
                }
            }
            Err(err) => format!("status query transport error: {err}"),
        };
        if attempt < max_attempts {
            between_attempts();
        }
    }
    Err(format!(
        "{alias} (node {node_id}) did not reach a healthy terminal state \
         ({RECOVERED_STATE_DATAPLANE_APPLIED}|{RECOVERED_STATE_EXIT_ACTIVE}) with a programmed \
         generation within the post-reboot recovery window ({max_attempts} attempts); \
         last status: {last_observation}"
    ))
}

/// Resolve the single macOS node the reboot-recovery validator drives. The
/// contract mirrors the sibling C6 validator — exactly one macOS node in the
/// topology, else fail closed.
fn macos_reboot_recovery_alias(ctx: &OrchestrationContext) -> Result<String, String> {
    let macos_aliases: Vec<String> = ctx
        .assignments
        .iter()
        .filter(|assignment| {
            ctx.adapters
                .get(&assignment.alias)
                .is_some_and(|adapter| adapter.platform() == VmGuestPlatform::Macos)
        })
        .map(|assignment| assignment.alias.clone())
        .collect();
    match macos_aliases.split_first() {
        None => Err(
            "no macOS node is present in this topology; the live reboot-recovery validator has no target"
                .to_owned(),
        ),
        Some((first, [])) => Ok(first.clone()),
        Some((_, rest)) => Err(format!(
            "expected exactly one macOS node for the live reboot-recovery validator, found {}",
            rest.len() + 1
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::adapter::node_adapter::NodeAdapter;
    use crate::vm_lab::orchestrator::error::{
        AdapterError, InstallReport, MembershipOwnerKey, MembershipSnapshot, NodeId,
        NodeMembershipPeer, TrafficTestResult, TunnelsList, ValidatorReport, WireguardPublicKey,
    };
    use crate::vm_lab::orchestrator::remote_shell::{
        RemoteExitStatus, RemoteShellError, RemoteStat,
    };
    use crate::vm_lab::orchestrator::role::NodeRole;
    use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
    use crate::vm_lab::orchestrator::source_archive::SourceArchive;
    use std::sync::Mutex;

    fn empty_ctx() -> OrchestrationContext {
        OrchestrationContext::new(
            Vec::<NodeRoleAssignment>::new(),
            std::env::temp_dir().join("macos-reboot-recovery-stage-tests"),
            "net".to_owned(),
        )
    }

    #[test]
    fn skips_with_reason_when_macos_is_not_elected() {
        // Every run that did not elect macOS for reboot recovery — a
        // Linux-only run included — must record a reported skip, never a
        // failure: the stage is in the default plan.
        let mut ctx = empty_ctx();
        assert!(
            !ctx.macos_reboot_recovery_elected,
            "a fresh context must default to not-elected (fail closed)"
        );
        let outcome =
            MacosRebootRecoveryValidationStage::new(1, test_shutdown_flag()).execute(&mut ctx);
        assert!(
            matches!(&outcome, StageOutcome::Skipped(reason) if reason.contains("not elected")),
            "a non-elected run must skip with a reason: {outcome:?}"
        );
    }

    #[test]
    fn fails_closed_when_elected_but_no_macos_node_exists() {
        let mut ctx = empty_ctx();
        ctx.macos_reboot_recovery_elected = true;
        let outcome =
            MacosRebootRecoveryValidationStage::new(1, test_shutdown_flag()).execute(&mut ctx);
        assert!(
            matches!(&outcome, StageOutcome::Failed(message) if message.contains("no macOS node")),
            "an elected run without a macOS node fails closed rather than skipping silently: {outcome:?}"
        );
    }

    #[test]
    fn stage_metadata_matches_the_catalog() {
        let stage = MacosRebootRecoveryValidationStage::new(4, test_shutdown_flag());
        assert_eq!(stage.id(), StageId::MacosRebootRecoveryValidation);
        assert_eq!(stage.name(), "validate_macos_reboot_recovery");
        assert_eq!(stage.fanout(), StageFanout::Once);
        assert_eq!(stage.dependencies(), &[StageId::ValidateBaselineRuntime]);
    }

    fn test_shutdown_flag() -> Arc<std::sync::atomic::AtomicBool> {
        Arc::new(std::sync::atomic::AtomicBool::new(false))
    }

    // ── Test doubles ─────────────────────────────────────────────

    /// What a fake adapter recorded about bundle distribution.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum BundleCall {
        VerifierKey(BundleKind),
        SignedBundle(BundleKind),
    }

    type CallLog = Arc<Mutex<Vec<(String, BundleCall)>>>;

    fn record(log: &CallLog, alias: &str, call: BundleCall) {
        log.lock()
            .expect("call log poisoned")
            .push((alias.to_owned(), call));
    }

    /// Adapter double: records every verifier-key + signed-bundle distribute
    /// it is asked to perform, and can ALSO serve as the exit-side issuer by
    /// materialising the bundle + verifier-key files `issue_bundles_to_dir`
    /// is contracted to produce. Only what the redistribution path touches is
    /// implemented; everything else fails loudly.
    #[derive(Debug)]
    struct FakeRecoveryAdapter {
        alias: String,
        platform: VmGuestPlatform,
        log: CallLog,
        /// When true, `issue_bundles_to_dir` writes the expected artifacts
        /// (64-hex verifier key + an empty signed bundle per node_id).
        act_as_issuer: bool,
        /// Status lines the shell returns, in order; the LAST one repeats.
        status_lines: Arc<Mutex<Vec<String>>>,
    }

    impl FakeRecoveryAdapter {
        fn recorded_calls(&self) -> Vec<BundleCall> {
            self.log
                .lock()
                .expect("call log poisoned")
                .iter()
                .filter(|(alias, _)| alias == &self.alias)
                .map(|(_, call)| call.clone())
                .collect()
        }
    }

    const TEST_NODE_ID_EXIT: &str = "node-exit-1";
    const TEST_NODE_ID_MACOS: &str = "node-macos-1";

    impl NodeAdapter for FakeRecoveryAdapter {
        fn platform(&self) -> VmGuestPlatform {
            self.platform
        }
        fn alias(&self) -> &str {
            &self.alias
        }
        fn install_daemon(
            &self,
            _source: &SourceArchive,
            _ctx: &OrchestrationContext,
        ) -> Result<InstallReport, AdapterError> {
            unimplemented!("not reached by the redistribution tests")
        }
        fn start_daemon(&self) -> Result<(), AdapterError> {
            unimplemented!("not reached by the redistribution tests")
        }
        fn stop_daemon(&self) -> Result<(), AdapterError> {
            unimplemented!("not reached by the redistribution tests")
        }
        fn restart_daemon(&self) -> Result<(), AdapterError> {
            unimplemented!("not reached by the redistribution tests")
        }
        fn uninstall_daemon(&self) -> Result<(), AdapterError> {
            unimplemented!("not reached by the redistribution tests")
        }
        fn issue_membership_owner_key(&self) -> Result<MembershipOwnerKey, AdapterError> {
            unimplemented!("not reached by the redistribution tests")
        }
        fn init_membership_snapshot(
            &self,
            _owner_key: &MembershipOwnerKey,
            _peers: &[NodeMembershipPeer],
        ) -> Result<MembershipSnapshot, AdapterError> {
            unimplemented!("not reached by the redistribution tests")
        }
        fn collect_wireguard_public_key(&self) -> Result<WireguardPublicKey, AdapterError> {
            unimplemented!("not reached by the redistribution tests")
        }
        fn collect_node_id(&self) -> Result<NodeId, AdapterError> {
            unimplemented!("not reached by the redistribution tests")
        }
        fn collect_gossip_identity(
            &self,
        ) -> Result<crate::vm_lab::orchestrator::error::GossipIdentity, AdapterError> {
            unimplemented!("not reached by the redistribution tests")
        }
        fn distribute_signed_bundle(
            &self,
            kind: BundleKind,
            _bundle_path: &Path,
        ) -> Result<(), AdapterError> {
            record(&self.log, &self.alias, BundleCall::SignedBundle(kind));
            Ok(())
        }
        fn distribute_verifier_key(
            &self,
            kind: BundleKind,
            _pub_key_path: &Path,
        ) -> Result<(), AdapterError> {
            record(&self.log, &self.alias, BundleCall::VerifierKey(kind));
            Ok(())
        }
        fn run_validator(
            &self,
            _op: crate::vm_lab::DaemonProbeOp,
            _extra_args: &[String],
        ) -> Result<ValidatorReport, AdapterError> {
            unimplemented!("not reached by the redistribution tests")
        }
        fn ping_mesh_peer(&self, _peer_mesh_ip: &str) -> Result<TrafficTestResult, AdapterError> {
            unimplemented!("not reached by the redistribution tests")
        }
        fn probe_denied_peer(&self, _denied_ip: &str) -> Result<TrafficTestResult, AdapterError> {
            unimplemented!("not reached by the redistribution tests")
        }
        fn collect_active_tunnels(&self) -> Result<TunnelsList, AdapterError> {
            unimplemented!("not reached by the redistribution tests")
        }
        fn shell_host(&self) -> Result<Arc<dyn RemoteShellHost>, AdapterError> {
            Ok(Arc::new(FakeShell {
                status_lines: Arc::clone(&self.status_lines),
            }))
        }
        fn collect_artifacts(&self, _dst: &Path) -> Result<(), AdapterError> {
            unimplemented!("not reached by the redistribution tests")
        }
        fn cleanup_runtime_state(&self) -> Result<(), AdapterError> {
            unimplemented!("not reached by the redistribution tests")
        }
        fn check_ssh_reachable(&self) -> Result<(), AdapterError> {
            unimplemented!("not reached by the redistribution tests")
        }
        fn endpoint(&self) -> String {
            "127.0.0.1:51820".to_owned()
        }
        fn collect_mesh_ip(&self) -> Result<String, AdapterError> {
            unimplemented!("not reached by the redistribution tests")
        }
        fn issue_bundles_to_dir(
            &self,
            kind: BundleKind,
            _env_content: &str,
            local_out_dir: &Path,
        ) -> Result<(), AdapterError> {
            if !self.act_as_issuer {
                unimplemented!("only the exit adapter acts as issuer in these tests")
            }
            // Materialise the verifier key (exactly 64 hex chars, newline-
            // terminated, as `validated_verifier_key_sha256` demands) and one
            // empty signed bundle per node in the mesh.
            let kind_str = match kind {
                BundleKind::Traversal => "traversal",
                BundleKind::Assignment => "assignment",
                BundleKind::DnsZone => "dns-zone",
                BundleKind::Membership => "membership",
            };
            let prefix = format!("rn-{kind_str}");
            std::fs::write(local_out_dir.join(format!("{prefix}.pub")), {
                let mut key = String::with_capacity(65);
                for _ in 0..32 {
                    key.push('a');
                    key.push('b');
                }
                key.push('\n');
                key
            })
            .map_err(|err| AdapterError::Io {
                message: err.to_string(),
            })?;
            for node_id in [TEST_NODE_ID_EXIT, TEST_NODE_ID_MACOS] {
                std::fs::write(
                    local_out_dir.join(format!("{prefix}-{node_id}.{kind_str}")),
                    b"signed-bundle-bytes",
                )
                .map_err(|err| AdapterError::Io {
                    message: err.to_string(),
                })?;
            }
            Ok(())
        }
    }

    /// Remote-shell double answering `run_argv` with the canned status lines.
    #[derive(Debug)]
    struct FakeShell {
        status_lines: Arc<Mutex<Vec<String>>>,
    }

    impl RemoteShellHost for FakeShell {
        fn read_file(&self, _remote_path: &str) -> Result<Vec<u8>, RemoteShellError> {
            unimplemented!("not reached by the redistribution tests")
        }
        fn write_file(
            &self,
            _remote_path: &str,
            _bytes: &[u8],
            _mode_octal: u16,
        ) -> Result<(), RemoteShellError> {
            unimplemented!("not reached by the redistribution tests")
        }
        fn stat(&self, _remote_path: &str) -> Result<RemoteStat, RemoteShellError> {
            unimplemented!("not reached by the redistribution tests")
        }
        fn run_argv(
            &self,
            _argv: &[&str],
            _env: &[(&str, &str)],
            _stdin: &[u8],
        ) -> Result<RemoteExitStatus, RemoteShellError> {
            let mut lines = self.status_lines.lock().expect("status lines poisoned");
            let line = if lines.len() == 1 {
                lines[0].clone()
            } else {
                lines.remove(0)
            };
            Ok(RemoteExitStatus {
                code: 0,
                stdout: line.into_bytes(),
                stderr: Vec::new(),
            })
        }
        fn tcp_send_recv(
            &self,
            _addr: &str,
            _payload: &[u8],
            _timeout: Duration,
        ) -> Result<Vec<u8>, RemoteShellError> {
            unimplemented!("not reached by the redistribution tests")
        }
    }

    /// Build a two-node context (exit issuer + macOS reboot target) wired for
    /// the redistribution tests.
    fn recovery_ctx() -> (OrchestrationContext, CallLog) {
        let log: CallLog = Arc::new(Mutex::new(Vec::new()));
        let status_lines = Arc::new(Mutex::new(vec![recovered_status_line()]));
        let mut ctx = empty_ctx();
        ctx.assignments = vec![
            NodeRoleAssignment {
                alias: "exit-1".to_owned(),
                role: NodeRole::Exit,
            },
            NodeRoleAssignment {
                alias: "macos-1".to_owned(),
                role: NodeRole::Client,
            },
        ];
        ctx.node_ids
            .insert("exit-1".to_owned(), TEST_NODE_ID_EXIT.to_owned());
        ctx.node_ids
            .insert("macos-1".to_owned(), TEST_NODE_ID_MACOS.to_owned());
        ctx.collected_pubkeys
            .insert("exit-1".to_owned(), WireguardPublicKey("a".repeat(64)));
        ctx.collected_pubkeys
            .insert("macos-1".to_owned(), WireguardPublicKey("b".repeat(64)));
        let exit_adapter = FakeRecoveryAdapter {
            alias: "exit-1".to_owned(),
            platform: VmGuestPlatform::Linux,
            log: Arc::clone(&log),
            act_as_issuer: true,
            status_lines: Arc::new(Mutex::new(vec![recovered_status_line()])),
        };
        let macos_adapter = FakeRecoveryAdapter {
            alias: "macos-1".to_owned(),
            platform: VmGuestPlatform::Macos,
            log: Arc::clone(&log),
            act_as_issuer: false,
            status_lines,
        };
        ctx.adapters
            .insert("exit-1".to_owned(), Box::new(exit_adapter));
        ctx.adapters
            .insert("macos-1".to_owned(), Box::new(macos_adapter));
        (ctx, log)
    }

    fn recovered_status_line() -> String {
        "state=DataplaneApplied path_programmed_peer_count=3 path_live_peer_count=3 node_role=client"
            .to_owned()
    }

    fn failclosed_status_line() -> String {
        "state=FailClosed path_programmed_peer_count=0 path_live_peer_count=0 node_role=client"
            .to_owned()
    }

    fn no_sleep() {}

    // ── Recovery-status parsing + criterion ──────────────────────

    #[test]
    fn recovery_status_parse_extracts_the_generation_fields() {
        let obs = parse_recovery_status(&failclosed_status_line());
        assert_eq!(obs.state.as_deref(), Some("FailClosed"));
        assert_eq!(obs.programmed_peer_count, 0);
        assert_eq!(obs.live_peer_count.as_deref(), Some("0"));
        let obs = parse_recovery_status(&recovered_status_line());
        assert_eq!(obs.state.as_deref(), Some("DataplaneApplied"));
        assert_eq!(obs.programmed_peer_count, 3);
        assert_eq!(obs.live_peer_count.as_deref(), Some("3"));
    }

    #[test]
    fn recovery_criterion_requires_allowlisted_state_and_programmed_generation() {
        // Both halves required: still-fail-closed never recovers…
        assert!(!node_has_recovered_generation(&parse_recovery_status(
            &failclosed_status_line()
        )));
        // …and a missing programmed count (fail-closed parse to 0) never
        // reads as recovered, even off FailClosed.
        assert!(!node_has_recovered_generation(&parse_recovery_status(
            "state=DataplaneApplied path_live_peer_count=2"
        )));
        assert!(node_has_recovered_generation(&parse_recovery_status(
            &recovered_status_line()
        )));
    }

    #[test]
    fn recovery_criterion_is_an_allowlist_of_healthy_terminal_states() {
        // Review F1: the criterion must ALLOWLIST the healthy terminal
        // states instead of negating one token. A MISSING state field…
        assert!(!node_has_recovered_generation(&parse_recovery_status(
            "path_programmed_peer_count=3"
        )));
        // …a drifted/renamed fail-closed family token, and every other
        // non-allowlisted state count as NOT recovered…
        assert!(!node_has_recovered_generation(&parse_recovery_status(
            "state=FailClosedDegraded path_programmed_peer_count=3"
        )));
        assert!(!node_has_recovered_generation(&parse_recovery_status(
            "state=Init path_programmed_peer_count=3"
        )));
        assert!(!node_has_recovered_generation(&parse_recovery_status(
            "state=ControlTrusted path_programmed_peer_count=3"
        )));
        // …while EACH allowlisted state with a programmed generation
        // recovers…
        for token in [
            RECOVERED_STATE_DATAPLANE_APPLIED,
            RECOVERED_STATE_EXIT_ACTIVE,
        ] {
            assert!(
                node_has_recovered_generation(&parse_recovery_status(&format!(
                    "state={token} path_programmed_peer_count=1"
                ))),
                "state={token} with a programmed generation must read as recovered"
            );
        }
        // …but an allowlisted state with ZERO programmed peers does not.
        assert!(!node_has_recovered_generation(&parse_recovery_status(
            "state=DataplaneApplied path_programmed_peer_count=0"
        )));
        assert!(!node_has_recovered_generation(&parse_recovery_status(
            "state=ExitActive path_live_peer_count=2"
        )));
    }

    #[test]
    fn recovered_state_names_are_pinned_to_the_daemon_enum() {
        // Review F1: the allowlist names must be REAL unit variants of the
        // daemon's `DataplaneState` — the enum whose Debug render the status
        // line carries as `state={:?}`. include_str! of the DEFINING FILE
        // keeps the pin honest: a daemon-side rename fails this test, and so
        // does a typo here.
        let phase10_rs = include_str!("../../../../../rustynetd/src/phase10.rs");
        let enum_start = phase10_rs
            .find("pub enum DataplaneState {")
            .expect("DataplaneState must be defined in crates/rustynetd/src/phase10.rs");
        let enum_block = &phase10_rs[enum_start..];
        let enum_end = enum_block
            .find('}')
            .expect("the DataplaneState enum block must terminate");
        let enum_block = &enum_block[..enum_end];
        // The two allowlisted healthy terminals must exist as unit variants…
        for token in [
            RECOVERED_STATE_DATAPLANE_APPLIED,
            RECOVERED_STATE_EXIT_ACTIVE,
        ] {
            assert!(
                enum_block.contains(&format!("\n    {token},\n")),
                "allowlisted state `{token}` must be a unit variant of DataplaneState"
            );
        }
        // …and the fail-closed terminal this criterion rejects must still
        // exist too, so a rename on either side is caught.
        assert!(
            enum_block.contains("\n    FailClosed,\n"),
            "the FailClosed unit variant must still exist in DataplaneState"
        );
    }

    #[test]
    fn poll_fails_with_exact_status_text_when_stuck_in_failclosed() {
        let shell = FakeShell {
            status_lines: Arc::new(Mutex::new(vec![failclosed_status_line()])),
        };
        let err = poll_generation_recovery(
            &shell,
            VmGuestPlatform::Macos,
            "macos-1",
            TEST_NODE_ID_MACOS,
            3,
            &mut no_sleep,
        )
        .expect_err("a FailClosed-stuck node must fail the poll");
        assert!(
            err.contains("FailClosed"),
            "the failure must name the fail-closed state: {err}"
        );
        assert!(
            err.contains(&failclosed_status_line()),
            "the failure must carry the EXACT last status line: {err}"
        );
    }

    #[test]
    fn poll_succeeds_only_once_the_generation_is_programmed() {
        // First two observations: daemon live but still fail-closed; third:
        // generation applied. The no-op sleeper keeps the test instant.
        let shell = FakeShell {
            status_lines: Arc::new(Mutex::new(vec![
                failclosed_status_line(),
                failclosed_status_line(),
                recovered_status_line(),
            ])),
        };
        let ok = poll_generation_recovery(
            &shell,
            VmGuestPlatform::Macos,
            "macos-1",
            TEST_NODE_ID_MACOS,
            5,
            &mut no_sleep,
        )
        .expect("a node that leaves FailClosed with a programmed generation recovers");
        assert_eq!(ok, recovered_status_line());
    }

    // ── Redistribution order + scoping ───────────────────────────

    #[test]
    fn redistributes_once_per_kind_and_polls_generation() {
        // Renamed (review F2): this test drives the seam implementation
        // DIRECTLY — it proves one fresh bundle per kind + verifier key per
        // kind + a successful generation poll, NOT the probe ordering (the
        // ordering contract is pinned by the source-slice test below; the
        // live exercise fn needs a real SSH target, so a runtime hook
        // recorder is not reachable from unit tests).
        let (mut ctx, log) = recovery_ctx();
        redistribute_fresh_bundles_and_await_generation(
            &mut ctx,
            "macos-1",
            TEST_NODE_ID_MACOS,
            1,
            &test_shutdown_flag(),
        )
        .expect("fresh bundle redistribution + generation poll must succeed on a recovering node");
        let calls = log.lock().expect("call log poisoned").clone();
        let traversal_signed = calls
            .iter()
            .filter(|(alias, call)| {
                alias == "macos-1"
                    && matches!(call, BundleCall::SignedBundle(BundleKind::Traversal))
            })
            .count();
        let dnszone_signed = calls
            .iter()
            .filter(|(alias, call)| {
                alias == "macos-1" && matches!(call, BundleCall::SignedBundle(BundleKind::DnsZone))
            })
            .count();
        assert_eq!(
            traversal_signed, 1,
            "exactly ONE fresh traversal bundle must be installed on the rebooted node: {calls:?}"
        );
        assert_eq!(
            dnszone_signed, 1,
            "exactly ONE fresh dns_zone bundle must be installed on the rebooted node: {calls:?}"
        );
        // The verifier-key barrier runs for the rebooted node too — one per
        // kind, before the signed bundles.
        for kind in [BundleKind::Traversal, BundleKind::DnsZone] {
            let verifier_calls = calls
                .iter()
                .filter(|(alias, call)| {
                    alias == "macos-1" && matches!(call, BundleCall::VerifierKey(k) if *k == kind)
                })
                .count();
            assert_eq!(
                verifier_calls, 1,
                "exactly one verifier-key distribution per kind through the existing barrier: {calls:?}"
            );
        }
        // Scoping: the OTHER node (the exit issuer) must receive NOTHING —
        // its recorded calls are distributions, and there must be none.
        let exit_distributions = calls.iter().filter(|(alias, _)| alias == "exit-1").count();
        assert_eq!(
            exit_distributions, 0,
            "a scoped redistribution must not touch the non-rebooted nodes: {calls:?}"
        );
    }

    #[test]
    fn redistribution_failure_fails_closed_with_context() {
        let (mut ctx, _log) = recovery_ctx();
        // No node_ids for the scope alias → the scoped distribution must
        // fail closed rather than distribute to nothing.
        let err = redistribute_fresh_bundles_and_await_generation(
            &mut ctx,
            "macos-missing",
            "node-missing",
            1,
            &test_shutdown_flag(),
        )
        .expect_err("redistributing to an unknown scope alias must fail closed");
        assert!(
            err.contains("fresh traversal bundle redistribution"),
            "the error must name the kind and the scope: {err}"
        );
    }

    // ── Probe-order contract, pinned at the source ───────────────

    #[test]
    fn source_pins_redistribution_before_the_pin_probe() {
        // The seam hook must run BEFORE the post-reboot pin/marker/boottime
        // probe is even constructed — reading the real source keeps this
        // order contractual rather than incidental. Review F2: the pin is
        // anchored INSIDE the exercise fn's body (sliced to the fn first),
        // so a doc-comment or unrelated occurrence of the call expression
        // elsewhere in mod.rs can never satisfy it, and the call expression
        // must occur EXACTLY ONCE in that body.
        let mod_rs = include_str!("../../mod.rs");
        let fn_start = mod_rs
            .find("pub fn exercise_macos_reboot_recovery_with_recovery_actions(")
            .expect("the seam-aware exercise fn must exist in vm_lab/mod.rs");
        let fn_end = mod_rs[fn_start..]
            .find("fn parse_macos_boottime_line(")
            .expect("the exercise fn must be followed by parse_macos_boottime_line");
        let fn_body = &mod_rs[fn_start..fn_start + fn_end];
        let seam_occurrences = fn_body.matches("post_daemon_live(&node_id)").count();
        assert_eq!(
            seam_occurrences, 1,
            "the mid-recovery seam hook must be invoked exactly once in the exercise fn body"
        );
        let seam = fn_body
            .find("post_daemon_live(&node_id)")
            .expect("the mid-recovery seam hook call must exist in the exercise fn body");
        let pin_probe = fn_body
            .find("let post_script = format!(")
            .expect("the post-reboot probe construction must exist in the exercise fn body");
        assert!(
            seam < pin_probe,
            "the redistribution seam ({seam}) must precede the pin probe ({pin_probe})"
        );
        // And the stage's seam implementation redistributes BEFORE it polls
        // — likewise sliced to the owning fn body so a doc-comment mention
        // of either call cannot satisfy the pin.
        let stage_rs = crate::vm_lab::implementation_source_slice(include_str!(
            "macos_reboot_recovery_validation.rs"
        ))
        .expect("macos_reboot_recovery_validation.rs implementation slice must parse");
        let stage_fn_start = stage_rs
            .find("fn redistribute_fresh_bundles_and_await_generation(")
            .expect("the seam implementation fn must exist in this file");
        let stage_fn_end = stage_rs[stage_fn_start..]
            .find("pub(crate) struct RecoveryStatusObservation")
            .expect("the seam implementation fn must precede RecoveryStatusObservation");
        let stage_fn_body = &stage_rs[stage_fn_start..stage_fn_start + stage_fn_end];
        let redistribute = stage_fn_body
            .find("distribute_bundle_kind_scoped(")
            .expect("the scoped redistribution call must exist in the seam fn body");
        let poll = stage_fn_body
            .find("poll_generation_recovery(")
            .expect("the generation poll call must exist in the seam fn body");
        assert!(
            redistribute < poll,
            "redistribution ({redistribute}) must precede the generation poll ({poll})"
        );
    }
}
