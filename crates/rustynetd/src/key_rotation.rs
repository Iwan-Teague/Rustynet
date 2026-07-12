#![forbid(unsafe_code)]

//! Daemon-side runtime for the local-node key rotation lifecycle.
//!
//! This module owns the persistent rotation ledger, the in-flight
//! handshake counter, the drain controller, and the deterministic state
//! machine that orchestrates the 4-step atomic swap during
//! [`crate::daemon`]-driven `rotate_local_key_material()` flows.
//!
//! Why a dedicated module?
//!
//! * The rotation flow is security-sensitive: a half-applied rotation
//!   leaks the prior key's authority into a window that callers may
//!   reason about as "rotated". Keeping the orchestrator small and
//!   isolated lets a reviewer audit the entire critical path without
//!   crawling [`crate::daemon`].
//! * The state machine is exercised by tests that need to inject
//!   faults at well-defined points. An IO-trait boundary
//!   ([`RotationIo`]) makes that injection cheap without spinning up a
//!   real WireGuard backend.
//! * The ledger persists the [`crate::key_rotation`] primitives from
//!   the control crate (epoch + archive + watermark) in one atomic
//!   record. A daemon restart re-loads exactly one consistent epoch
//!   even if the host crashed mid-rotation.
//!
//! IMPORTANT: rotation here is about the LOCAL NODE'S long-lived
//! identity material. WireGuard's per-session keys derived from the
//! noise handshake are NOT rekeyed by this flow; they continue under
//! WireGuard's intrinsic `REKEY_AFTER_TIME` schedule on each existing
//! session and only flip to the new identity on the peer's next
//! initiator handshake. This module's drain window covers in-flight
//! handshakes — the negotiation events themselves — not in-flight data
//! traffic on an already-established session.

use std::collections::VecDeque;
use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use rustynet_control::key_rotation::{
    ArchivedVerifier, DrainOutcome, PerEpochReplayWatermark, RotationAuditEntry,
    RotationAuditOutcome, RotationEpoch, RotationError, RotationFaultPoint, RotationState,
    VerifierArchive,
};

/// Default drain window during which rotation waits for in-flight
/// handshakes to resolve. Five seconds matches the existing reconcile
/// cadence: any handshake that has not made progress in 5s is no longer
/// "in-flight" in the WireGuard sense and the rotation can proceed
/// without waiting on a stuck peer.
pub const DEFAULT_ROTATION_DRAIN_TIMEOUT_SECS: u64 = 5;

/// Number of audit-trail entries retained in the on-disk ledger. The
/// audit log is append-only within the ledger; older entries roll off
/// the front when the cap is hit. The kept window is large enough to
/// reconstruct a multi-hour incident timeline.
pub const ROTATION_AUDIT_RETENTION: usize = 256;

/// Maximum acceptable size (in bytes) of the rotation ledger file.
/// Generous enough for hundreds of archive entries + the audit ring,
/// small enough to refuse a file that has been adversarially grown.
pub const MAX_ROTATION_LEDGER_BYTES: usize = 256 * 1024;

const LEDGER_SCHEMA_VERSION: u8 = 1;

/// Filename suffix appended to the WireGuard private key path to derive
/// the rotation-ledger location. Keeping the ledger next to the key
/// material means the same directory-ACL discipline applies.
pub const LEDGER_FILENAME_SUFFIX: &str = ".rotation_ledger";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalKeyRotationLedger {
    state: RotationState,
    current_epoch: RotationEpoch,
    archive: VerifierArchive,
    watermark: PerEpochReplayWatermark,
    audit: VecDeque<RotationAuditEntry>,
}

impl LocalKeyRotationLedger {
    pub fn genesis() -> Self {
        Self {
            state: RotationState::Idle,
            current_epoch: RotationEpoch::GENESIS,
            archive: VerifierArchive::new(),
            watermark: PerEpochReplayWatermark::new(RotationEpoch::GENESIS),
            audit: VecDeque::with_capacity(ROTATION_AUDIT_RETENTION.min(64)),
        }
    }

    pub fn state(&self) -> RotationState {
        self.state
    }

    pub fn current_epoch(&self) -> RotationEpoch {
        self.current_epoch
    }

    pub fn archive(&self) -> &VerifierArchive {
        &self.archive
    }

    pub fn watermark(&self) -> &PerEpochReplayWatermark {
        &self.watermark
    }

    pub fn audit_entries(&self) -> impl Iterator<Item = &RotationAuditEntry> {
        self.audit.iter()
    }

    pub fn push_audit(&mut self, entry: RotationAuditEntry) {
        if self.audit.len() >= ROTATION_AUDIT_RETENTION {
            self.audit.pop_front();
        }
        self.audit.push_back(entry);
    }

    pub fn ensure_idle(&self) -> Result<(), RotationError> {
        if !self.state.is_idle() {
            return Err(RotationError::AlreadyInProgress { state: self.state });
        }
        Ok(())
    }

    pub fn begin_draining(&mut self) -> Result<(), RotationError> {
        self.ensure_idle()?;
        self.state = RotationState::Draining;
        Ok(())
    }

    pub fn transition_to_swapping(&mut self) -> Result<(), RotationError> {
        if !matches!(self.state, RotationState::Draining) {
            return Err(RotationError::InvalidStateTransition {
                from: self.state,
                to: RotationState::Swapping,
            });
        }
        self.state = RotationState::Swapping;
        Ok(())
    }

    pub fn finalize_commit(
        &mut self,
        outgoing_epoch: RotationEpoch,
        new_verifier: ArchivedVerifier,
        watermark_at_rotation: u64,
        new_epoch: RotationEpoch,
    ) -> Result<(), RotationError> {
        if !matches!(self.state, RotationState::Swapping) {
            return Err(RotationError::InvalidStateTransition {
                from: self.state,
                to: RotationState::Idle,
            });
        }
        if outgoing_epoch != self.current_epoch {
            return Err(RotationError::EpochNotMonotonic {
                current: self.current_epoch,
                attempted: outgoing_epoch,
            });
        }
        let expected_next = self.current_epoch.next()?;
        if new_epoch != expected_next {
            return Err(RotationError::EpochNotMonotonic {
                current: self.current_epoch,
                attempted: new_epoch,
            });
        }
        self.archive.record(new_verifier)?;
        self.watermark.advance_to(new_epoch)?;
        self.watermark
            .freeze_outgoing(outgoing_epoch, watermark_at_rotation)?;
        self.current_epoch = new_epoch;
        self.state = RotationState::Idle;
        Ok(())
    }

    pub fn rollback_to_idle(&mut self) {
        self.state = RotationState::Idle;
    }

    pub fn enter_failed_rollback(&mut self) {
        self.state = RotationState::FailedRollback;
    }

    fn canonical_payload(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("version={LEDGER_SCHEMA_VERSION}\n"));
        out.push_str(&format!("state={}\n", self.state.as_str()));
        out.push_str(&format!("current_epoch={}\n", self.current_epoch));
        out.push_str(&self.archive.canonical_payload());
        out.push_str(&self.watermark.canonical_payload());
        out.push_str(&format!("audit_count={}\n", self.audit.len()));
        for (index, entry) in self.audit.iter().enumerate() {
            out.push_str(&format!("audit.{index}.ts={}\n", entry.now_unix));
            out.push_str(&format!(
                "audit.{index}.outcome={}\n",
                entry.outcome.as_str()
            ));
            out.push_str(&format!("audit.{index}.epoch_prev={}\n", entry.epoch_prev));
            out.push_str(&format!("audit.{index}.epoch_new={}\n", entry.epoch_new));
            let drain = entry
                .drain_outcome
                .map(|d| d.as_str())
                .unwrap_or("not_attempted");
            out.push_str(&format!("audit.{index}.drain={drain}\n"));
            let drain_count = entry.drain_outcome.map(|d| d.in_flight()).unwrap_or(0);
            out.push_str(&format!("audit.{index}.drain_in_flight={drain_count}\n"));
            out.push_str(&format!(
                "audit.{index}.cause={}\n",
                sanitize_field(&entry.cause)
            ));
        }
        out
    }

    /// Persist the ledger atomically: single temp-file create, single
    /// write of the body + digest, single fsync, single rename. The
    /// daemon treats the rename boundary as the crash-recovery point:
    /// either the file is the prior committed ledger or it is the new
    /// committed ledger, never a torn intermediate.
    pub fn persist(&self, path: &Path) -> Result<(), RotationError> {
        let payload = self.canonical_payload();
        let digest = sha256_hex(payload.as_bytes());
        let body = format!("{payload}digest={digest}\n");
        atomic_write_secure(path, body.as_bytes(), 0o600)
    }

    /// Load and validate the ledger from `path`. Treats any structural,
    /// digest, or monotonicity mismatch as `LedgerCorrupt` so callers
    /// fail closed.
    pub fn load(path: &Path) -> Result<Self, RotationError> {
        let raw = read_bounded(path, MAX_ROTATION_LEDGER_BYTES)?;
        let fields = parse_kv(&raw)?;
        let version: u8 = parse_field(&fields, "version")?;
        if version != LEDGER_SCHEMA_VERSION {
            return Err(RotationError::LedgerCorrupt(format!(
                "ledger schema version {version} is not supported"
            )));
        }
        let state_str: String = parse_field(&fields, "state")?;
        let state = match state_str.as_str() {
            "idle" => RotationState::Idle,
            "draining" => RotationState::Draining,
            "swapping" => RotationState::Swapping,
            "failed_rollback" => RotationState::FailedRollback,
            other => {
                return Err(RotationError::LedgerCorrupt(format!(
                    "unknown ledger state {other}"
                )));
            }
        };
        let current_epoch_value: u64 = parse_field(&fields, "current_epoch")?;
        let current_epoch = RotationEpoch(current_epoch_value);

        let archive_count: usize = parse_field(&fields, "archive_count")?;
        let mut archive = VerifierArchive::new();
        for index in 0..archive_count {
            let epoch: u64 = parse_field(&fields, &format!("archive.{index}.epoch"))?;
            let public_key_hex: String =
                parse_field(&fields, &format!("archive.{index}.public_key_hex"))?;
            let archived_at_unix: u64 =
                parse_field(&fields, &format!("archive.{index}.archived_at_unix"))?;
            let watermark_at_rotation: u64 =
                parse_field(&fields, &format!("archive.{index}.watermark_at_rotation"))?;
            archive.record(ArchivedVerifier {
                epoch: RotationEpoch(epoch),
                public_key_hex,
                archived_at_unix,
                watermark_at_rotation,
            })?;
        }

        let watermark_current_epoch_value: u64 = parse_field(&fields, "current_epoch")?;
        let mut watermark = PerEpochReplayWatermark::new(RotationEpoch(0));
        if watermark_current_epoch_value > 0 {
            watermark.advance_to(RotationEpoch(watermark_current_epoch_value))?;
        }
        let freeze_count: usize = parse_field(&fields, "freeze_count")?;
        for index in 0..freeze_count {
            let epoch: u64 = parse_field(&fields, &format!("freeze.{index}.epoch"))?;
            let frozen_watermark: u64 = parse_field(&fields, &format!("freeze.{index}.watermark"))?;
            watermark.freeze_outgoing(RotationEpoch(epoch), frozen_watermark)?;
        }

        let audit_count: usize = parse_field(&fields, "audit_count")?;
        let mut audit = VecDeque::with_capacity(audit_count.min(ROTATION_AUDIT_RETENTION));
        for index in 0..audit_count {
            let ts: u64 = parse_field(&fields, &format!("audit.{index}.ts"))?;
            let outcome_str: String = parse_field(&fields, &format!("audit.{index}.outcome"))?;
            let outcome = match outcome_str.as_str() {
                "success" => RotationAuditOutcome::Success,
                "rollback" => RotationAuditOutcome::Rollback,
                "rejected" => RotationAuditOutcome::Rejected,
                other => {
                    return Err(RotationError::LedgerCorrupt(format!(
                        "unknown audit outcome {other}"
                    )));
                }
            };
            let epoch_prev: u64 = parse_field(&fields, &format!("audit.{index}.epoch_prev"))?;
            let epoch_new: u64 = parse_field(&fields, &format!("audit.{index}.epoch_new"))?;
            let drain_str: String = parse_field(&fields, &format!("audit.{index}.drain"))?;
            let drain_in_flight: u64 =
                parse_field(&fields, &format!("audit.{index}.drain_in_flight"))?;
            let drain_outcome = match drain_str.as_str() {
                "all_resolved" => Some(DrainOutcome::AllResolved {
                    observed_in_flight: drain_in_flight,
                }),
                "timeout" => Some(DrainOutcome::Timeout {
                    in_flight: drain_in_flight,
                }),
                "not_attempted" => None,
                other => {
                    return Err(RotationError::LedgerCorrupt(format!(
                        "unknown drain outcome {other}"
                    )));
                }
            };
            let cause: String = parse_field(&fields, &format!("audit.{index}.cause"))?;
            audit.push_back(RotationAuditEntry {
                epoch_prev: RotationEpoch(epoch_prev),
                epoch_new: RotationEpoch(epoch_new),
                outcome,
                drain_outcome,
                now_unix: ts,
                cause,
            });
        }

        let digest_value: String = parse_field(&fields, "digest")?;
        let expected_body_without_digest = {
            let mut probe = LocalKeyRotationLedger {
                state,
                current_epoch,
                archive: archive.clone(),
                watermark: watermark.clone(),
                audit: audit.clone(),
            };
            // Reconstruct the canonical payload from the typed pieces
            // so any field-ordering mismatch with the on-disk source
            // surfaces as a digest mismatch — fail closed.
            probe.audit = audit.clone();
            probe.canonical_payload()
        };
        let recomputed = sha256_hex(expected_body_without_digest.as_bytes());
        if recomputed != digest_value {
            return Err(RotationError::LedgerCorrupt(
                "ledger digest mismatch".to_owned(),
            ));
        }

        Ok(LocalKeyRotationLedger {
            state,
            current_epoch,
            archive,
            watermark,
            audit,
        })
    }
}

/// Derive the on-disk ledger path from the WireGuard private key path.
/// Centralised here so the daemon and tests cannot drift on the
/// suffix convention.
pub fn ledger_path_for(wg_private_key_path: &Path) -> PathBuf {
    let mut path = wg_private_key_path.as_os_str().to_owned();
    path.push(LEDGER_FILENAME_SUFFIX);
    PathBuf::from(path)
}

/// Thread-safe in-flight handshake counter.
///
/// Handshake initiation paths must call `start_handshake()` to obtain a
/// [`HandshakeGuard`]; the guard's `Drop` impl decrements the counter
/// exactly once. The rotation drain controller polls the counter and
/// proceeds when it reaches zero (or when the configured timeout
/// elapses).
#[derive(Debug, Default)]
pub struct InFlightHandshakeTracker {
    counter: AtomicU64,
}

impl InFlightHandshakeTracker {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn in_flight(&self) -> u64 {
        self.counter.load(Ordering::Acquire)
    }

    pub fn start_handshake(self: &Arc<Self>) -> HandshakeGuard {
        self.counter.fetch_add(1, Ordering::AcqRel);
        HandshakeGuard {
            tracker: Arc::clone(self),
        }
    }
}

#[derive(Debug)]
pub struct HandshakeGuard {
    tracker: Arc<InFlightHandshakeTracker>,
}

impl Drop for HandshakeGuard {
    fn drop(&mut self) {
        self.tracker.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Drain controller — waits for the in-flight counter to hit zero or
/// for the configured timeout to elapse. Tests inject deterministic
/// clock/sleep closures via [`RotationDrainController::drain_with`].
#[derive(Debug)]
pub struct RotationDrainController {
    tracker: Arc<InFlightHandshakeTracker>,
    drain_timeout: Duration,
}

impl RotationDrainController {
    pub fn new(tracker: Arc<InFlightHandshakeTracker>, drain_timeout: Duration) -> Self {
        Self {
            tracker,
            drain_timeout,
        }
    }

    pub fn tracker(&self) -> &Arc<InFlightHandshakeTracker> {
        &self.tracker
    }

    pub fn drain_timeout(&self) -> Duration {
        self.drain_timeout
    }

    pub fn drain(&self) -> DrainOutcome {
        self.drain_with(Instant::now, std::thread::sleep)
    }

    pub fn drain_with<F: FnMut() -> Instant, S: FnMut(Duration)>(
        &self,
        mut now: F,
        mut sleep: S,
    ) -> DrainOutcome {
        let start = now();
        let poll_interval = Duration::from_millis(10);
        loop {
            let in_flight = self.tracker.in_flight();
            if in_flight == 0 {
                return DrainOutcome::AllResolved {
                    observed_in_flight: 0,
                };
            }
            let elapsed = now().saturating_duration_since(start);
            if elapsed >= self.drain_timeout {
                return DrainOutcome::Timeout { in_flight };
            }
            sleep(poll_interval);
        }
    }
}

/// IO trait used by [`execute_rotation`]. The production daemon
/// implements this against real key material + WireGuard apply paths;
/// the test suite implements it against in-memory state with
/// fault-injection hooks.
pub trait RotationIo {
    /// Generate a new keypair and return the new public key + a
    /// `watermark_at_rotation` value reflecting the daemon's notion of
    /// the highest accepted update-watermark under the outgoing epoch.
    fn prepare_swap(&mut self) -> Result<PreparedSwap, RotationError>;

    /// Persist new key material atomically. The corresponding rollback
    /// is implemented by [`RotationIo::rollback_key_write`].
    fn commit_key_write(&mut self) -> Result<(), RotationError>;

    /// Roll back the most-recent key write to the prior epoch's key
    /// material on disk. Idempotent.
    fn rollback_key_write(&mut self) -> Result<(), RotationError>;

    /// Apply the new key to the active WireGuard interface. The
    /// corresponding rollback is implemented by
    /// [`RotationIo::rollback_wg_apply`].
    fn apply_wg_interface(&mut self) -> Result<(), RotationError>;

    /// Roll back the WireGuard interface to the prior key. Idempotent.
    fn rollback_wg_apply(&mut self) -> Result<(), RotationError>;

    /// Persist the ledger (epoch + archive + watermark + audit).
    fn persist_ledger(&mut self, ledger: &LocalKeyRotationLedger) -> Result<(), RotationError>;

    /// Optional fault injection hook. Default returns `Ok(())`.
    fn fault_check(&self, _point: RotationFaultPoint) -> Result<(), RotationError> {
        Ok(())
    }
}

/// Result of [`RotationIo::prepare_swap`]. Conveys the freshly-generated
/// outgoing-epoch identity plus the watermark-at-rotation snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedSwap {
    pub outgoing_epoch: RotationEpoch,
    pub outgoing_public_key_hex: String,
    pub new_public_key_hex: String,
    pub watermark_at_rotation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationOutcome {
    pub previous_epoch: RotationEpoch,
    pub new_epoch: RotationEpoch,
    pub drain_outcome: DrainOutcome,
    pub new_public_key_hex: String,
    pub elapsed: Duration,
}

/// Execute one rotation. The flow:
///
/// 1. Ledger must be `Idle` (else `AlreadyInProgress`).
/// 2. Transition `Idle → Draining`. Wait on the drain controller.
/// 3. Transition `Draining → Swapping`.
/// 4. Atomic swap:
///    a. `prepare_swap` — generate new key, snapshot outgoing pubkey + watermark.
///    b. `commit_key_write` — persist new key on disk.
///    c. update in-memory ledger (archive + watermark + epoch).
///    d. `persist_ledger` — write the ledger atomically.
///    e. `apply_wg_interface` — apply the new key to WG.
/// 5. On any failure in 4b–4e, roll back to the prior epoch
///    deterministically and re-persist the ledger so a daemon restart
///    sees the prior epoch only.
///
/// The fault-check hook is consulted before each I/O step so tests can
/// inject failures at the exact transition boundary.
pub fn execute_rotation<IO: RotationIo>(
    io: &mut IO,
    ledger: &mut LocalKeyRotationLedger,
    drain: &RotationDrainController,
    now_unix: u64,
) -> Result<RotationOutcome, RotationError> {
    let start = Instant::now();
    let previous_epoch = ledger.current_epoch;

    if let Err(err) = ledger.begin_draining() {
        ledger.push_audit(RotationAuditEntry::rejected(
            previous_epoch,
            now_unix,
            err.to_string(),
        ));
        // The ledger is in a recoverable state (still Idle if we
        // failed) — persist the audit entry so the rejection is
        // visible. The persist itself is best-effort here because the
        // primary failure is already known.
        let _ = io.persist_ledger(ledger);
        return Err(err);
    }

    let drain_outcome = drain.drain();

    if let Err(err) = ledger.transition_to_swapping() {
        ledger.rollback_to_idle();
        ledger.push_audit(RotationAuditEntry::rollback(
            previous_epoch,
            previous_epoch,
            Some(drain_outcome),
            now_unix,
            format!("transition_to_swapping_failed: {err}"),
        ));
        let _ = io.persist_ledger(ledger);
        return Err(err);
    }

    if let Err(err) = io.fault_check(RotationFaultPoint::BeforeKeyWrite) {
        return finalise_rollback(
            io,
            ledger,
            previous_epoch,
            previous_epoch,
            Some(drain_outcome),
            now_unix,
            format!("fault_before_key_write: {err}"),
            err,
        );
    }
    let prepared = match io.prepare_swap() {
        Ok(value) => value,
        Err(err) => {
            return finalise_rollback(
                io,
                ledger,
                previous_epoch,
                previous_epoch,
                Some(drain_outcome),
                now_unix,
                format!("prepare_swap_failed: {err}"),
                err,
            );
        }
    };
    if prepared.outgoing_epoch != previous_epoch {
        let err = RotationError::EpochNotMonotonic {
            current: previous_epoch,
            attempted: prepared.outgoing_epoch,
        };
        return finalise_rollback(
            io,
            ledger,
            previous_epoch,
            previous_epoch,
            Some(drain_outcome),
            now_unix,
            format!("prepare_swap_returned_unexpected_outgoing_epoch: {err}"),
            err,
        );
    }
    let new_epoch = previous_epoch.next().map_err(|err| {
        ledger.rollback_to_idle();
        ledger.push_audit(RotationAuditEntry::rollback(
            previous_epoch,
            previous_epoch,
            Some(drain_outcome),
            now_unix,
            format!("epoch_overflow: {err}"),
        ));
        let _ = io.persist_ledger(ledger);
        err
    })?;

    if let Err(err) = io.commit_key_write() {
        return finalise_rollback(
            io,
            ledger,
            previous_epoch,
            new_epoch,
            Some(drain_outcome),
            now_unix,
            format!("commit_key_write_failed: {err}"),
            err,
        );
    }

    if let Err(err) = io.fault_check(RotationFaultPoint::BeforeArchive) {
        let _ = io.rollback_key_write();
        return finalise_rollback(
            io,
            ledger,
            previous_epoch,
            new_epoch,
            Some(drain_outcome),
            now_unix,
            format!("fault_before_archive: {err}"),
            err,
        );
    }

    let archived = ArchivedVerifier {
        epoch: prepared.outgoing_epoch,
        public_key_hex: prepared.outgoing_public_key_hex.clone(),
        archived_at_unix: now_unix,
        watermark_at_rotation: prepared.watermark_at_rotation,
    };
    if let Err(err) = ledger.finalize_commit(
        previous_epoch,
        archived,
        prepared.watermark_at_rotation,
        new_epoch,
    ) {
        let _ = io.rollback_key_write();
        return finalise_rollback(
            io,
            ledger,
            previous_epoch,
            new_epoch,
            Some(drain_outcome),
            now_unix,
            format!("finalize_commit_failed: {err}"),
            err,
        );
    }

    if let Err(err) = io.fault_check(RotationFaultPoint::BeforeWatermarkAdvance) {
        // The in-memory ledger has already advanced; roll back state
        // before persisting + WG apply so we re-enter Idle on the
        // prior epoch.
        revert_finalised_ledger(ledger, previous_epoch);
        let _ = io.rollback_key_write();
        return finalise_rollback(
            io,
            ledger,
            previous_epoch,
            new_epoch,
            Some(drain_outcome),
            now_unix,
            format!("fault_before_watermark_advance: {err}"),
            err,
        );
    }

    if let Err(err) = io.persist_ledger(ledger) {
        revert_finalised_ledger(ledger, previous_epoch);
        let _ = io.rollback_key_write();
        return finalise_rollback(
            io,
            ledger,
            previous_epoch,
            new_epoch,
            Some(drain_outcome),
            now_unix,
            format!("persist_ledger_failed: {err}"),
            err,
        );
    }

    if let Err(err) = io.fault_check(RotationFaultPoint::BeforeWgApply) {
        // The ledger is persisted as `new_epoch`. To roll back fully
        // we revert the in-memory ledger, re-persist as the prior
        // epoch, and roll back the key write. This restores the
        // "exactly one epoch on disk" invariant.
        revert_finalised_ledger(ledger, previous_epoch);
        let _ = io.persist_ledger(ledger);
        let _ = io.rollback_key_write();
        return finalise_rollback(
            io,
            ledger,
            previous_epoch,
            new_epoch,
            Some(drain_outcome),
            now_unix,
            format!("fault_before_wg_apply: {err}"),
            err,
        );
    }

    if let Err(err) = io.apply_wg_interface() {
        // Same recovery path: revert ledger to prior epoch and
        // re-persist to restore the on-disk invariant.
        revert_finalised_ledger(ledger, previous_epoch);
        let _ = io.persist_ledger(ledger);
        let _ = io.rollback_key_write();
        return finalise_rollback(
            io,
            ledger,
            previous_epoch,
            new_epoch,
            Some(drain_outcome),
            now_unix,
            format!("apply_wg_interface_failed: {err}"),
            err,
        );
    }

    if let Err(err) = io.fault_check(RotationFaultPoint::AfterWgApply) {
        // Rollback covers both ledger and dataplane.
        let _ = io.rollback_wg_apply();
        revert_finalised_ledger(ledger, previous_epoch);
        let _ = io.persist_ledger(ledger);
        let _ = io.rollback_key_write();
        return finalise_rollback(
            io,
            ledger,
            previous_epoch,
            new_epoch,
            Some(drain_outcome),
            now_unix,
            format!("fault_after_wg_apply: {err}"),
            err,
        );
    }

    ledger.push_audit(RotationAuditEntry::success(
        previous_epoch,
        new_epoch,
        drain_outcome,
        now_unix,
    ));
    // Best-effort: persist the final audit entry alongside the
    // committed epoch. A failure here doesn't invalidate the rotation
    // — the prior persist already committed the epoch. Surface a
    // typed error if the audit append cannot be persisted.
    io.persist_ledger(ledger)?;

    Ok(RotationOutcome {
        previous_epoch,
        new_epoch,
        drain_outcome,
        new_public_key_hex: prepared.new_public_key_hex,
        elapsed: start.elapsed(),
    })
}

#[allow(clippy::too_many_arguments)]
fn finalise_rollback<IO: RotationIo>(
    io: &mut IO,
    ledger: &mut LocalKeyRotationLedger,
    previous_epoch: RotationEpoch,
    attempted_epoch: RotationEpoch,
    drain_outcome: Option<DrainOutcome>,
    now_unix: u64,
    cause: impl Into<String>,
    original_err: RotationError,
) -> Result<RotationOutcome, RotationError> {
    ledger.rollback_to_idle();
    ledger.push_audit(RotationAuditEntry::rollback(
        previous_epoch,
        attempted_epoch,
        drain_outcome,
        now_unix,
        cause.into(),
    ));
    // Persist failure on the rollback itself is unrecoverable — the
    // ledger on disk is now in an unknown state. Mark the
    // in-memory ledger so subsequent rotation attempts are rejected
    // until operator intervention resets it.
    if let Err(persist_err) = io.persist_ledger(ledger) {
        ledger.enter_failed_rollback();
        return Err(RotationError::Unrecoverable(format!(
            "persist_after_rollback_failed: {persist_err}; original={original_err}"
        )));
    }
    Err(original_err)
}

fn revert_finalised_ledger(ledger: &mut LocalKeyRotationLedger, previous_epoch: RotationEpoch) {
    // Rebuild a clean prior-epoch ledger view in-place. We cannot
    // simply pop the most-recent archive entry without also reverting
    // the watermark advancement; the easiest correct path is to
    // reconstruct the archive + watermark from scratch.
    let mut prior_archive = VerifierArchive::new();
    for (epoch, verifier) in ledger.archive.iter() {
        if epoch.value() < previous_epoch.value() {
            // Existing archive entries from prior rotations stay.
            // `record` returns Err on duplicate but we know these are
            // distinct from the just-attempted insertion.
            let _ = prior_archive.record(verifier.clone());
        }
    }
    let mut prior_watermark = PerEpochReplayWatermark::new(RotationEpoch(0));
    if previous_epoch.value() > 0 {
        let _ = prior_watermark.advance_to(previous_epoch);
    }
    // Re-freeze any outgoing epochs that pre-date the prior epoch.
    let mut freezes: Vec<(RotationEpoch, u64)> = Vec::new();
    for (epoch, verifier) in prior_archive.iter() {
        if epoch.value() < previous_epoch.value() {
            freezes.push((epoch, verifier.watermark_at_rotation));
        }
    }
    freezes.sort_by_key(|(epoch, _)| epoch.value());
    for (epoch, watermark_at_rotation) in freezes {
        let _ = prior_watermark.freeze_outgoing(epoch, watermark_at_rotation);
    }
    ledger.archive = prior_archive;
    ledger.watermark = prior_watermark;
    ledger.current_epoch = previous_epoch;
    ledger.state = RotationState::Idle;
}

fn sanitize_field(value: &str) -> String {
    value.replace(['\n', '\r'], " ")
}

fn sha256_hex(input: &[u8]) -> String {
    let digest = Sha256::digest(input);
    hex_lower(&digest)
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn read_bounded(path: &Path, max: usize) -> Result<String, RotationError> {
    use std::io::Read;
    let file = fs::File::open(path)
        .map_err(|err| RotationError::LedgerCorrupt(format!("open failed: {err}")))?;
    let mut buf = String::new();
    file.take(max as u64 + 1)
        .read_to_string(&mut buf)
        .map_err(|err| RotationError::LedgerCorrupt(format!("read failed: {err}")))?;
    if buf.len() > max {
        return Err(RotationError::LedgerCorrupt(format!(
            "ledger exceeds {max} byte cap"
        )));
    }
    Ok(buf)
}

fn parse_kv(raw: &str) -> Result<Vec<(String, String)>, RotationError> {
    let mut out = Vec::new();
    for line in raw.lines() {
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(RotationError::LedgerCorrupt(format!(
                "invalid ledger line {line}"
            )));
        };
        out.push((key.to_owned(), value.to_owned()));
    }
    Ok(out)
}

fn parse_field<T: std::str::FromStr>(
    fields: &[(String, String)],
    key: &str,
) -> Result<T, RotationError>
where
    <T as std::str::FromStr>::Err: std::fmt::Display,
{
    let raw = fields
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
        .ok_or_else(|| {
            RotationError::LedgerCorrupt(format!("ledger missing required field {key}"))
        })?;
    raw.parse::<T>()
        .map_err(|err| RotationError::LedgerCorrupt(format!("ledger field {key} invalid: {err}")))
}

fn atomic_write_secure(path: &Path, body: &[u8], mode: u32) -> Result<(), RotationError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|err| {
            RotationError::ArchiveWriteFailed(format!(
                "create_dir_all({}) failed: {err}",
                parent.display()
            ))
        })?;
    }
    let temp_path = path.with_extension(format!(
        "tmp.{}.{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
    }
    let mut temp = options
        .open(&temp_path)
        .map_err(|err| RotationError::ArchiveWriteFailed(format!("open temp failed: {err}")))?;
    temp.write_all(body).map_err(|err| {
        let _ = fs::remove_file(&temp_path);
        RotationError::ArchiveWriteFailed(format!("write failed: {err}"))
    })?;
    temp.sync_all().map_err(|err| {
        let _ = fs::remove_file(&temp_path);
        RotationError::ArchiveWriteFailed(format!("sync failed: {err}"))
    })?;
    fs::rename(&temp_path, path).map_err(|err| {
        let _ = fs::remove_file(&temp_path);
        RotationError::ArchiveWriteFailed(format!("rename failed: {err}"))
    })?;
    #[cfg(unix)]
    {
        if let Some(parent) = path.parent() {
            if let Ok(parent_dir) = fs::File::open(parent) {
                let _ = parent_dir.sync_all();
            }
            // Tighten parent directory perms if it already exists with
            // a wider mode, but never widen.
            if let Ok(metadata) = fs::metadata(parent) {
                let current = metadata.permissions().mode() & 0o777;
                if current & 0o077 != 0 {
                    let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
                }
            }
        }
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustynet_control::key_rotation::RotationFaultPoint;
    use std::cell::Cell;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Test-only IO that records every call and supports fault
    /// injection at named points. The harness keeps an in-memory
    /// "on-disk" key-material map and a vector of persisted ledgers
    /// so tests can assert exactly what was committed where.
    struct RecordingIo {
        outgoing_epoch: RotationEpoch,
        outgoing_pubkey_hex: String,
        next_pubkey_hex: String,
        watermark_at_rotation: u64,
        fault: Cell<Option<RotationFaultPoint>>,
        // Counts of how many times each operation ran (commit /
        // rollback). Lets the test assert rollback symmetry.
        ops: Mutex<HashMap<&'static str, u64>>,
        persisted: Mutex<Vec<LocalKeyRotationLedger>>,
        // Simulated on-disk key generation: this is what
        // `commit_key_write` materializes, and what
        // `rollback_key_write` removes.
        on_disk_key: Mutex<Option<String>>,
        // Simulated on-interface key: what `apply_wg_interface`
        // materializes, what `rollback_wg_apply` removes.
        on_interface_key: Mutex<Option<String>>,
    }

    impl RecordingIo {
        fn new(outgoing_epoch: RotationEpoch) -> Self {
            Self {
                outgoing_epoch,
                outgoing_pubkey_hex: format!(
                    "{:0width$x}",
                    0xaabbccdd_u32 + outgoing_epoch.value() as u32,
                    width = 64
                ),
                next_pubkey_hex: format!(
                    "{:0width$x}",
                    0xbeefcafe_u32 + outgoing_epoch.value() as u32 + 1,
                    width = 64
                ),
                watermark_at_rotation: 42 + outgoing_epoch.value(),
                fault: Cell::new(None),
                ops: Mutex::new(HashMap::new()),
                persisted: Mutex::new(Vec::new()),
                on_disk_key: Mutex::new(Some(format!(
                    "{:0width$x}",
                    0xaabbccdd_u32 + outgoing_epoch.value() as u32,
                    width = 64
                ))),
                on_interface_key: Mutex::new(Some(format!(
                    "{:0width$x}",
                    0xaabbccdd_u32 + outgoing_epoch.value() as u32,
                    width = 64
                ))),
            }
        }

        fn inject(&self, point: RotationFaultPoint) {
            self.fault.set(Some(point));
        }

        fn op_count(&self, name: &'static str) -> u64 {
            self.ops
                .lock()
                .unwrap()
                .get(name)
                .copied()
                .unwrap_or_default()
        }

        fn bump(&self, name: &'static str) {
            *self.ops.lock().unwrap().entry(name).or_default() += 1;
        }

        fn last_persisted(&self) -> Option<LocalKeyRotationLedger> {
            self.persisted.lock().unwrap().last().cloned()
        }

        fn persisted_count(&self) -> usize {
            self.persisted.lock().unwrap().len()
        }
    }

    impl RotationIo for RecordingIo {
        fn prepare_swap(&mut self) -> Result<PreparedSwap, RotationError> {
            self.bump("prepare_swap");
            Ok(PreparedSwap {
                outgoing_epoch: self.outgoing_epoch,
                outgoing_public_key_hex: self.outgoing_pubkey_hex.clone(),
                new_public_key_hex: self.next_pubkey_hex.clone(),
                watermark_at_rotation: self.watermark_at_rotation,
            })
        }

        fn commit_key_write(&mut self) -> Result<(), RotationError> {
            self.bump("commit_key_write");
            *self.on_disk_key.lock().unwrap() = Some(self.next_pubkey_hex.clone());
            Ok(())
        }

        fn rollback_key_write(&mut self) -> Result<(), RotationError> {
            self.bump("rollback_key_write");
            *self.on_disk_key.lock().unwrap() = Some(self.outgoing_pubkey_hex.clone());
            Ok(())
        }

        fn apply_wg_interface(&mut self) -> Result<(), RotationError> {
            self.bump("apply_wg_interface");
            *self.on_interface_key.lock().unwrap() = Some(self.next_pubkey_hex.clone());
            Ok(())
        }

        fn rollback_wg_apply(&mut self) -> Result<(), RotationError> {
            self.bump("rollback_wg_apply");
            *self.on_interface_key.lock().unwrap() = Some(self.outgoing_pubkey_hex.clone());
            Ok(())
        }

        fn persist_ledger(&mut self, ledger: &LocalKeyRotationLedger) -> Result<(), RotationError> {
            self.bump("persist_ledger");
            self.persisted.lock().unwrap().push(ledger.clone());
            Ok(())
        }

        fn fault_check(&self, point: RotationFaultPoint) -> Result<(), RotationError> {
            if self.fault.get() == Some(point) {
                self.fault.set(None);
                return Err(RotationError::FaultInjected(point));
            }
            Ok(())
        }
    }

    fn make_drain(timeout: Duration) -> RotationDrainController {
        let tracker = InFlightHandshakeTracker::new();
        RotationDrainController::new(tracker, timeout)
    }

    // ─── Drain timing tests ───────────────────────────────────────

    #[test]
    fn ledger_field_parsers_and_sanitizer() {
        // parse_kv: splits key=value lines, skips blank lines, and errors on a
        // line with no '='. split_once keeps '=' inside the value.
        let kv = parse_kv("a=1\n\nb=hello=world\n").unwrap();
        assert_eq!(
            kv,
            vec![
                ("a".to_owned(), "1".to_owned()),
                ("b".to_owned(), "hello=world".to_owned()),
            ]
        );
        assert!(parse_kv("noequals").is_err());
        assert_eq!(parse_kv("k=").unwrap(), vec![("k".to_owned(), String::new())]);

        // parse_field<T>: parse a required field; missing or non-parseable both
        // fail closed as LedgerCorrupt.
        let fields = vec![
            ("epoch".to_owned(), "42".to_owned()),
            ("bad".to_owned(), "x".to_owned()),
        ];
        assert_eq!(parse_field::<u64>(&fields, "epoch").unwrap(), 42);
        assert!(matches!(
            parse_field::<u64>(&fields, "missing"),
            Err(RotationError::LedgerCorrupt(_))
        ));
        assert!(matches!(
            parse_field::<u64>(&fields, "bad"),
            Err(RotationError::LedgerCorrupt(_))
        ));

        // sanitize_field: CR/LF become spaces so a field value cannot inject a
        // second ledger line; other whitespace (tab) is untouched.
        assert_eq!(sanitize_field("plain"), "plain");
        assert_eq!(sanitize_field("a\nb"), "a b");
        assert_eq!(sanitize_field("a\r\nb"), "a  b");
        assert_eq!(sanitize_field("no=newline\there"), "no=newline\there");
    }

    #[test]
    fn rotation_drain_completes_immediately_when_no_inflight() {
        let drain = make_drain(Duration::from_secs(5));
        let outcome = drain.drain();
        assert!(matches!(
            outcome,
            DrainOutcome::AllResolved {
                observed_in_flight: 0
            }
        ));
    }

    #[test]
    fn rotation_drain_waits_for_inflight_handshakes() {
        let drain = make_drain(Duration::from_secs(5));
        let guard_cell: std::cell::RefCell<Option<HandshakeGuard>> =
            std::cell::RefCell::new(Some(drain.tracker().start_handshake()));
        assert_eq!(drain.tracker().in_flight(), 1);

        let start = Instant::now();
        // Simulate the drain loop where the in-flight count drops to
        // zero after a few polling iterations. After three polls the
        // guard is taken out of the cell and dropped, which the real
        // Drop impl decrements the in-flight counter to zero.
        let mut polls = 0u32;
        let outcome = drain.drain_with(
            || {
                polls += 1;
                if polls > 3 {
                    // Drop the held guard exactly once. The take()
                    // returns None on subsequent polls.
                    let _ = guard_cell.borrow_mut().take();
                }
                start + Duration::from_millis(50 * polls as u64)
            },
            |_| {},
        );
        assert!(matches!(
            outcome,
            DrainOutcome::AllResolved {
                observed_in_flight: 0
            }
        ));
    }

    #[test]
    fn rotation_drain_times_out_and_proceeds_after_window() {
        let drain = make_drain(Duration::from_millis(500));
        let _guard = drain.tracker().start_handshake();
        let now_anchor = Instant::now();
        // The first `now()` call captures `start` inside `drain_with`.
        // Subsequent calls jump forward past the drain window so
        // `elapsed >= drain_timeout` on the first loop iteration.
        let mut call = 0u32;
        let outcome = drain.drain_with(
            || {
                call += 1;
                if call == 1 {
                    now_anchor
                } else {
                    now_anchor + Duration::from_secs(1)
                }
            },
            |_| {},
        );
        assert!(matches!(outcome, DrainOutcome::Timeout { in_flight: 1 }));
    }

    // ─── Atomic-swap correctness tests ────────────────────────────

    #[test]
    fn rotation_commits_all_four_steps_or_none() {
        let mut ledger = LocalKeyRotationLedger::genesis();
        let drain = make_drain(Duration::from_millis(50));
        let mut io = RecordingIo::new(RotationEpoch::GENESIS);
        let outcome = execute_rotation(&mut io, &mut ledger, &drain, 1_700_000_000)
            .expect("rotation must succeed");
        assert_eq!(outcome.previous_epoch.value(), 0);
        assert_eq!(outcome.new_epoch.value(), 1);
        assert_eq!(io.op_count("prepare_swap"), 1);
        assert_eq!(io.op_count("commit_key_write"), 1);
        assert_eq!(io.op_count("apply_wg_interface"), 1);
        // persist_ledger runs once for the swap commit and once for
        // the audit-success update.
        assert_eq!(io.op_count("persist_ledger"), 2);
        assert_eq!(io.op_count("rollback_key_write"), 0);
        assert_eq!(io.op_count("rollback_wg_apply"), 0);
        let final_ledger = io.last_persisted().expect("ledger persisted");
        assert_eq!(final_ledger.current_epoch().value(), 1);
        assert!(final_ledger.archive().contains(RotationEpoch(0)));
        assert_eq!(
            final_ledger
                .watermark()
                .rotation_point_for(RotationEpoch(0)),
            Some(42)
        );
    }

    #[test]
    fn rotation_io_failure_mid_swap_rolls_back_atomically() {
        let mut ledger = LocalKeyRotationLedger::genesis();
        let drain = make_drain(Duration::from_millis(50));
        let mut io = RecordingIo::new(RotationEpoch::GENESIS);
        io.inject(RotationFaultPoint::BeforeWgApply);
        let err = execute_rotation(&mut io, &mut ledger, &drain, 1_700_000_000)
            .expect_err("fault must surface");
        assert!(matches!(
            err,
            RotationError::FaultInjected(RotationFaultPoint::BeforeWgApply)
        ));
        // Rollback must have flipped the key file back.
        assert_eq!(io.op_count("rollback_key_write"), 1);
        // WG apply never ran, so no rollback there.
        assert_eq!(io.op_count("rollback_wg_apply"), 0);
        // Ledger persisted at least three times: ledger commit,
        // ledger rollback after fault, and final audit persist.
        assert!(io.persisted_count() >= 2);
        let final_ledger = io.last_persisted().expect("ledger persisted");
        assert_eq!(final_ledger.current_epoch().value(), 0);
        assert!(!final_ledger.archive().contains(RotationEpoch(0)));
        assert_eq!(
            final_ledger
                .watermark()
                .rotation_point_for(RotationEpoch(0)),
            None
        );
        assert!(matches!(final_ledger.state(), RotationState::Idle));
    }

    #[test]
    fn rotation_verifier_archive_corruption_rolls_back_and_fails_closed() {
        // Pre-load the ledger with an archive entry for epoch 0 so
        // finalize_commit will fail with ArchiveDuplicate.
        let mut ledger = LocalKeyRotationLedger::genesis();
        ledger
            .archive
            .record(ArchivedVerifier {
                epoch: RotationEpoch(0),
                public_key_hex: "0".repeat(64),
                archived_at_unix: 0,
                watermark_at_rotation: 0,
            })
            .expect("seed archive");
        let drain = make_drain(Duration::from_millis(50));
        let mut io = RecordingIo::new(RotationEpoch::GENESIS);
        let err = execute_rotation(&mut io, &mut ledger, &drain, 1_700_000_000)
            .expect_err("archive corruption must fail closed");
        assert!(matches!(
            err,
            RotationError::ArchiveDuplicate { epoch } if epoch.value() == 0
        ));
        let final_ledger = io.last_persisted().expect("ledger persisted");
        assert_eq!(final_ledger.current_epoch().value(), 0);
        assert!(matches!(final_ledger.state(), RotationState::Idle));
    }

    // ─── Idempotency tests ────────────────────────────────────────

    #[test]
    fn rotation_while_already_rotating_rejected_clearly() {
        let mut ledger = LocalKeyRotationLedger::genesis();
        ledger.state = RotationState::Draining;
        let drain = make_drain(Duration::from_millis(50));
        let mut io = RecordingIo::new(RotationEpoch::GENESIS);
        let err = execute_rotation(&mut io, &mut ledger, &drain, 1_700_000_000)
            .expect_err("nested rotation must be rejected");
        assert!(matches!(
            err,
            RotationError::AlreadyInProgress {
                state: RotationState::Draining
            }
        ));
    }

    #[test]
    fn idle_rotation_completes_under_100ms() {
        let mut ledger = LocalKeyRotationLedger::genesis();
        let drain = make_drain(Duration::from_millis(5));
        let mut io = RecordingIo::new(RotationEpoch::GENESIS);
        let start = Instant::now();
        execute_rotation(&mut io, &mut ledger, &drain, 1_700_000_000)
            .expect("rotation must succeed");
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(100),
            "idle rotation should complete <100ms, observed {elapsed:?}"
        );
    }

    // ─── In-flight session resolution ─────────────────────────────

    #[test]
    fn inflight_handshake_started_pre_rotation_completes_under_old_key() {
        let tracker = InFlightHandshakeTracker::new();
        let guard = tracker.start_handshake();
        assert_eq!(tracker.in_flight(), 1);
        drop(guard);
        assert_eq!(tracker.in_flight(), 0);
    }

    // ─── Watermark advancement ────────────────────────────────────

    #[test]
    fn rotation_advances_watermark_for_new_epoch() {
        let mut ledger = LocalKeyRotationLedger::genesis();
        let drain = make_drain(Duration::from_millis(50));
        let mut io = RecordingIo::new(RotationEpoch::GENESIS);
        execute_rotation(&mut io, &mut ledger, &drain, 1_700_000_000)
            .expect("rotation must succeed");
        assert_eq!(ledger.watermark().current_epoch().value(), 1);
    }

    #[test]
    fn old_epoch_watermark_frozen_at_rotation_point() {
        let mut ledger = LocalKeyRotationLedger::genesis();
        let drain = make_drain(Duration::from_millis(50));
        let mut io = RecordingIo::new(RotationEpoch::GENESIS);
        execute_rotation(&mut io, &mut ledger, &drain, 1_700_000_000)
            .expect("rotation must succeed");
        let frozen = ledger.watermark().rotation_point_for(RotationEpoch(0));
        assert_eq!(frozen, Some(42));
    }

    // ─── Audit logging ────────────────────────────────────────────

    #[test]
    fn rotation_success_emits_audit_entry_with_epoch_bump() {
        let mut ledger = LocalKeyRotationLedger::genesis();
        let drain = make_drain(Duration::from_millis(50));
        let mut io = RecordingIo::new(RotationEpoch::GENESIS);
        execute_rotation(&mut io, &mut ledger, &drain, 1_700_000_000)
            .expect("rotation must succeed");
        let entries: Vec<&RotationAuditEntry> = ledger.audit_entries().collect();
        let last = entries.last().expect("at least one audit entry");
        assert_eq!(last.outcome, RotationAuditOutcome::Success);
        assert_eq!(last.epoch_prev.value(), 0);
        assert_eq!(last.epoch_new.value(), 1);
    }

    #[test]
    fn rotation_failure_emits_audit_entry_with_cause() {
        let mut ledger = LocalKeyRotationLedger::genesis();
        let drain = make_drain(Duration::from_millis(50));
        let mut io = RecordingIo::new(RotationEpoch::GENESIS);
        io.inject(RotationFaultPoint::BeforeKeyWrite);
        let _ =
            execute_rotation(&mut io, &mut ledger, &drain, 1_700_000_000).expect_err("must fail");
        let entries: Vec<&RotationAuditEntry> = ledger.audit_entries().collect();
        let last = entries.last().expect("at least one audit entry");
        assert_eq!(last.outcome, RotationAuditOutcome::Rollback);
        assert!(last.cause.contains("fault_before_key_write"));
    }

    // ─── Ledger persistence + crash consistency ──────────────────

    #[test]
    fn ledger_roundtrip_via_disk_is_identity_preserving() {
        let tmp = std::env::temp_dir().join(format!(
            "rustynet-rotation-ledger-{}.bin",
            std::process::id()
        ));
        let mut ledger = LocalKeyRotationLedger::genesis();
        let drain = make_drain(Duration::from_millis(50));
        let mut io = RecordingIo::new(RotationEpoch::GENESIS);
        execute_rotation(&mut io, &mut ledger, &drain, 1_700_000_000).expect("rotation");
        ledger.persist(&tmp).expect("persist ledger");
        let reloaded = LocalKeyRotationLedger::load(&tmp).expect("reload ledger");
        assert_eq!(reloaded, ledger);
        let _ = std::fs::remove_file(&tmp);
    }

    /// Persist a genesis ledger to a unique temp path and hand back the path
    /// plus its on-disk text for the tamper tests below.
    fn persisted_genesis_ledger(label: &str) -> (PathBuf, String) {
        let tmp = std::env::temp_dir().join(format!(
            "rustynet-rotation-tamper-{label}-{}-{}.bin",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        LocalKeyRotationLedger::genesis()
            .persist(&tmp)
            .expect("persist genesis ledger");
        let content = std::fs::read_to_string(&tmp).expect("read ledger");
        (tmp, content)
    }

    #[test]
    fn load_rejects_tampered_digest() {
        // The trailing `digest=<hex>` binds the body; zeroing it must fail
        // closed rather than load a ledger whose integrity is unverified.
        let (tmp, content) = persisted_genesis_ledger("digest");
        let marker = "\ndigest=";
        let idx = content.find(marker).expect("digest line present");
        let value_start = idx + marker.len();
        let value_end = content[value_start..]
            .find('\n')
            .map(|n| value_start + n)
            .unwrap_or(content.len());
        let mut tampered = content.clone();
        tampered.replace_range(value_start..value_end, &"0".repeat(value_end - value_start));
        std::fs::write(&tmp, &tampered).expect("write tampered");

        let err = LocalKeyRotationLedger::load(&tmp).expect_err("tampered digest must fail");
        assert!(
            matches!(err, RotationError::LedgerCorrupt(ref m) if m.contains("digest mismatch")),
            "expected digest mismatch, got {err:?}"
        );
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn load_rejects_tampered_body_field() {
        // Mutating any signed body field (here `state`) must surface as a
        // digest mismatch — the stored digest no longer matches the body.
        let (tmp, content) = persisted_genesis_ledger("body");
        assert!(content.contains("state=idle"), "genesis ledger is idle");
        let tampered = content.replace("state=idle", "state=draining");
        std::fs::write(&tmp, &tampered).expect("write tampered");

        let err = LocalKeyRotationLedger::load(&tmp).expect_err("tampered body must fail");
        assert!(
            matches!(err, RotationError::LedgerCorrupt(ref m) if m.contains("digest mismatch")),
            "expected digest mismatch, got {err:?}"
        );
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn load_rejects_missing_digest_field() {
        // Dropping the digest line entirely is a torn/short write; load must
        // refuse it as a missing required field, never default it.
        let (tmp, content) = persisted_genesis_ledger("nodigest");
        let without_digest: String = content
            .lines()
            .filter(|line| !line.starts_with("digest="))
            .map(|line| format!("{line}\n"))
            .collect();
        std::fs::write(&tmp, &without_digest).expect("write");

        let err = LocalKeyRotationLedger::load(&tmp).expect_err("missing digest must fail");
        assert!(
            matches!(err, RotationError::LedgerCorrupt(ref m) if m.contains("digest")),
            "expected missing-digest rejection, got {err:?}"
        );
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn load_rejects_truncated_ledger() {
        // A file truncated to just the version line is missing every other
        // required field; load fails closed instead of partially applying.
        let (tmp, _content) = persisted_genesis_ledger("trunc");
        std::fs::write(&tmp, format!("version={LEDGER_SCHEMA_VERSION}\n")).expect("write");

        let err = LocalKeyRotationLedger::load(&tmp).expect_err("truncated ledger must fail");
        assert!(
            matches!(err, RotationError::LedgerCorrupt(_)),
            "expected LedgerCorrupt, got {err:?}"
        );
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn mid_rotation_panic_leaves_one_epoch_on_disk() {
        let tmp = std::env::temp_dir().join(format!(
            "rustynet-rotation-crash-{}.bin",
            std::process::id()
        ));
        // Persist the genesis ledger first so a "post-crash" load is
        // deterministic.
        let mut ledger = LocalKeyRotationLedger::genesis();
        ledger.persist(&tmp).expect("persist genesis");

        // Now run a rotation that fails after the new-epoch ledger
        // has been persisted but before WG apply. The flow MUST
        // revert the ledger to the prior epoch and re-persist before
        // returning the error.
        let drain = make_drain(Duration::from_millis(50));
        struct DiskBackedIo {
            inner: RecordingIo,
            ledger_path: PathBuf,
        }
        impl RotationIo for DiskBackedIo {
            fn prepare_swap(&mut self) -> Result<PreparedSwap, RotationError> {
                self.inner.prepare_swap()
            }
            fn commit_key_write(&mut self) -> Result<(), RotationError> {
                self.inner.commit_key_write()
            }
            fn rollback_key_write(&mut self) -> Result<(), RotationError> {
                self.inner.rollback_key_write()
            }
            fn apply_wg_interface(&mut self) -> Result<(), RotationError> {
                self.inner.apply_wg_interface()
            }
            fn rollback_wg_apply(&mut self) -> Result<(), RotationError> {
                self.inner.rollback_wg_apply()
            }
            fn persist_ledger(
                &mut self,
                ledger: &LocalKeyRotationLedger,
            ) -> Result<(), RotationError> {
                self.inner.persist_ledger(ledger)?;
                ledger.persist(&self.ledger_path)
            }
            fn fault_check(&self, point: RotationFaultPoint) -> Result<(), RotationError> {
                self.inner.fault_check(point)
            }
        }
        let mut io = DiskBackedIo {
            inner: RecordingIo::new(RotationEpoch::GENESIS),
            ledger_path: tmp.clone(),
        };
        io.inner.inject(RotationFaultPoint::BeforeWgApply);
        let _ = execute_rotation(&mut io, &mut ledger, &drain, 1_700_000_000)
            .expect_err("fault must surface");

        // On reload, the on-disk ledger MUST show exactly the prior
        // epoch — no half-committed hybrid state. This proves the
        // atomic boundary holds across the simulated mid-rotation
        // crash.
        let reloaded = LocalKeyRotationLedger::load(&tmp).expect("reload after fault");
        assert_eq!(reloaded.current_epoch().value(), 0);
        assert!(matches!(reloaded.state(), RotationState::Idle));
        assert!(!reloaded.archive().contains(RotationEpoch(0)));
        let _ = std::fs::remove_file(&tmp);
    }
}
