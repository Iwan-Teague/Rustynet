#![forbid(unsafe_code)]

//! Primitives for the Rustynet local-node key rotation lifecycle.
//!
//! The rotation lifecycle is the daemon's hardened workflow for replacing
//! the long-lived per-node identity material that signs gossip / membership
//! bundles and drives the backend transport noise handshake. The lifecycle is
//! deliberately strict:
//!
//! * Each rotation produces a monotonic [`RotationEpoch`] which is
//!   persisted with the key material so a daemon restart re-loads exactly
//!   one consistent epoch (never a hybrid prior/new state).
//! * The outgoing verifying key is archived under its epoch tag in
//!   [`VerifierArchive`] so historical bundles signed under the prior
//!   epoch can still be verified within the per-epoch replay window.
//! * The per-epoch replay watermark ([`PerEpochReplayWatermark`]) freezes
//!   the maximum accepted update-watermark of an outgoing epoch at the
//!   exact moment rotation fires; any later bundle that claims to be from
//!   that epoch but carries a watermark past the freeze point is rejected
//!   as a signature-context violation rather than a normal replay.
//! * Bundles signed under a future epoch (one the daemon has not yet
//!   recorded) are rejected as an unknown-epoch failure — the daemon
//!   cannot trust an epoch tag it never issued.
//!
//! The types in this module are transport-free and have no IO. The
//! daemon-side state machine that ties them to actual file IO + tunnel
//! interface operations lives in `rustynetd::key_rotation`.

use std::collections::BTreeMap;
use std::fmt;

/// Monotonic identifier for a single rotation generation.
///
/// Epoch `0` is the genesis epoch issued the first time the local node
/// initialises identity material. Each successful rotation bumps the
/// epoch by exactly one. A daemon that observes a non-monotonic epoch on
/// disk MUST fail closed: the on-disk record is treated as corrupt rather
/// than rolled back silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RotationEpoch(pub u64);

impl RotationEpoch {
    pub const GENESIS: RotationEpoch = RotationEpoch(0);

    pub fn value(self) -> u64 {
        self.0
    }

    pub fn next(self) -> Result<RotationEpoch, RotationError> {
        self.0
            .checked_add(1)
            .map(RotationEpoch)
            .ok_or(RotationError::EpochOverflow)
    }
}

impl fmt::Display for RotationEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Coarse phase of the local rotation state machine.
///
/// The phase is observable so callers (IPC, audit, diagnostics) can reject
/// nested rotation requests deterministically. The transitions are:
///
/// ```text
///   Idle ──request──► Draining ──drain complete──► Swapping ──commit──► Idle
///                          │                            │
///                          │                            └──any step fails──► FailedRollback ──recovered──► Idle
///                          └──rotation aborted──► Idle
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationState {
    Idle,
    Draining,
    Swapping,
    FailedRollback,
}

impl RotationState {
    pub fn as_str(self) -> &'static str {
        match self {
            RotationState::Idle => "idle",
            RotationState::Draining => "draining",
            RotationState::Swapping => "swapping",
            RotationState::FailedRollback => "failed_rollback",
        }
    }

    pub fn is_idle(self) -> bool {
        matches!(self, RotationState::Idle)
    }

    pub fn is_in_progress(self) -> bool {
        matches!(self, RotationState::Draining | RotationState::Swapping)
    }
}

impl fmt::Display for RotationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Single archived verifier key, indexed by the rotation epoch under
/// which it was current. Stored alongside the watermark observed at the
/// moment the rotation fired so the verifier can answer "was bundle X
/// signed before the rotation point or after it?" deterministically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchivedVerifier {
    pub epoch: RotationEpoch,
    pub public_key_hex: String,
    pub archived_at_unix: u64,
    pub watermark_at_rotation: u64,
}

/// Bounded archive of verifier keys retained across rotations.
///
/// The archive is bounded so a misbehaving daemon (or repeated forced
/// rotation in a small test) cannot grow the archive without limit. When
/// the archive exceeds [`VerifierArchive::DEFAULT_RETENTION`] entries the
/// oldest entries beyond the retention window are pruned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierArchive {
    entries: BTreeMap<u64, ArchivedVerifier>,
    retention: usize,
}

impl VerifierArchive {
    /// Default retention window. Keeping the most recent 32 verifier
    /// keys means the daemon can validate bundles emitted under any of
    /// the last 32 rotations — a security/scale balance that
    /// comfortably covers normal operator rotation cadences.
    pub const DEFAULT_RETENTION: usize = 32;

    pub fn new() -> Self {
        Self::with_retention(Self::DEFAULT_RETENTION)
    }

    pub fn with_retention(retention: usize) -> Self {
        let bounded = if retention == 0 { 1 } else { retention };
        Self {
            entries: BTreeMap::new(),
            retention: bounded,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn retention(&self) -> usize {
        self.retention
    }

    /// Insert (or replace) an archive entry for the given epoch. Repeated
    /// inserts under the same epoch fail closed — the rotation flow MUST
    /// archive an epoch exactly once.
    pub fn record(&mut self, verifier: ArchivedVerifier) -> Result<(), RotationError> {
        if self.entries.contains_key(&verifier.epoch.value()) {
            return Err(RotationError::ArchiveDuplicate {
                epoch: verifier.epoch,
            });
        }
        let epoch_value = verifier.epoch.value();
        self.entries.insert(epoch_value, verifier);
        self.prune_to_retention();
        Ok(())
    }

    fn prune_to_retention(&mut self) {
        while self.entries.len() > self.retention {
            // BTreeMap iteration is ordered, so removing the first key
            // drops the oldest epoch.
            let oldest = self
                .entries
                .keys()
                .next()
                .copied()
                .expect("retention prune only runs with non-empty archive");
            self.entries.remove(&oldest);
        }
    }

    pub fn lookup(&self, epoch: RotationEpoch) -> Option<&ArchivedVerifier> {
        self.entries.get(&epoch.value())
    }

    pub fn contains(&self, epoch: RotationEpoch) -> bool {
        self.entries.contains_key(&epoch.value())
    }

    pub fn iter(&self) -> impl Iterator<Item = (RotationEpoch, &ArchivedVerifier)> {
        self.entries
            .iter()
            .map(|(epoch, verifier)| (RotationEpoch(*epoch), verifier))
    }

    /// Canonical key=value rendering of the archive contents. Used by
    /// the daemon ledger writer to emit a deterministic, hashable
    /// representation prior to fsync.
    pub fn canonical_payload(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("archive_count={}\n", self.entries.len()));
        for (index, (_, verifier)) in self.entries.iter().enumerate() {
            out.push_str(&format!("archive.{index}.epoch={}\n", verifier.epoch));
            out.push_str(&format!(
                "archive.{index}.public_key_hex={}\n",
                verifier.public_key_hex
            ));
            out.push_str(&format!(
                "archive.{index}.archived_at_unix={}\n",
                verifier.archived_at_unix
            ));
            out.push_str(&format!(
                "archive.{index}.watermark_at_rotation={}\n",
                verifier.watermark_at_rotation
            ));
        }
        out
    }
}

impl Default for VerifierArchive {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-epoch replay-watermark store.
///
/// The watermark answers the question "given that a bundle claims to be
/// signed under rotation epoch `E`, what is the highest update-watermark
/// the daemon is willing to accept under that epoch?" The semantics are:
///
/// * If `E` is the currently-active rotation epoch
///   ([`PerEpochReplayWatermark::current_epoch`]), the bundle is
///   accepted up to whatever the normal membership replay cache allows;
///   the per-epoch watermark imposes no extra ceiling.
/// * If `E` is an outgoing (archived) rotation epoch, the bundle is
///   accepted ONLY when its update-watermark is `<=` the freeze point
///   that was recorded at the moment rotation past `E` fired.
/// * If `E` is unknown to the watermark store, the bundle is rejected
///   as a signature-context violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerEpochReplayWatermark {
    current_epoch: RotationEpoch,
    rotation_points: BTreeMap<u64, u64>,
}

impl PerEpochReplayWatermark {
    pub fn new(current_epoch: RotationEpoch) -> Self {
        Self {
            current_epoch,
            rotation_points: BTreeMap::new(),
        }
    }

    pub fn current_epoch(&self) -> RotationEpoch {
        self.current_epoch
    }

    /// Set a new current epoch. Used after a rotation commits.
    pub fn advance_to(&mut self, new_epoch: RotationEpoch) -> Result<(), RotationError> {
        if new_epoch.value() <= self.current_epoch.value() {
            return Err(RotationError::EpochNotMonotonic {
                current: self.current_epoch,
                attempted: new_epoch,
            });
        }
        self.current_epoch = new_epoch;
        Ok(())
    }

    /// Record the watermark freeze point for an outgoing epoch.
    /// Repeated recording for the same epoch fails closed — the daemon
    /// must freeze each outgoing epoch exactly once.
    pub fn freeze_outgoing(
        &mut self,
        outgoing_epoch: RotationEpoch,
        watermark_at_rotation: u64,
    ) -> Result<(), RotationError> {
        if outgoing_epoch.value() >= self.current_epoch.value() {
            return Err(RotationError::FreezeOnActiveEpoch {
                current: self.current_epoch,
                attempted: outgoing_epoch,
            });
        }
        if self.rotation_points.contains_key(&outgoing_epoch.value()) {
            return Err(RotationError::WatermarkDuplicate {
                epoch: outgoing_epoch,
            });
        }
        self.rotation_points
            .insert(outgoing_epoch.value(), watermark_at_rotation);
        Ok(())
    }

    pub fn rotation_point_for(&self, epoch: RotationEpoch) -> Option<u64> {
        self.rotation_points.get(&epoch.value()).copied()
    }

    /// Validate that a bundle tagged with `epoch_tag` and carrying
    /// `update_watermark` is acceptable under the per-epoch policy.
    pub fn validate_bundle(
        &self,
        epoch_tag: RotationEpoch,
        update_watermark: u64,
    ) -> Result<(), RotationError> {
        if epoch_tag.value() > self.current_epoch.value() {
            return Err(RotationError::UnknownEpoch { epoch: epoch_tag });
        }
        if epoch_tag.value() == self.current_epoch.value() {
            return Ok(());
        }
        match self.rotation_points.get(&epoch_tag.value()) {
            None => Err(RotationError::UnknownEpoch { epoch: epoch_tag }),
            Some(freeze) => {
                if update_watermark > *freeze {
                    Err(RotationError::WatermarkPastRotationPoint {
                        epoch: epoch_tag,
                        bundle_watermark: update_watermark,
                        freeze_point: *freeze,
                    })
                } else {
                    Ok(())
                }
            }
        }
    }

    pub fn canonical_payload(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("current_epoch={}\n", self.current_epoch));
        out.push_str(&format!("freeze_count={}\n", self.rotation_points.len()));
        for (index, (epoch, freeze)) in self.rotation_points.iter().enumerate() {
            out.push_str(&format!("freeze.{index}.epoch={epoch}\n"));
            out.push_str(&format!("freeze.{index}.watermark={freeze}\n"));
        }
        out
    }
}

/// Outcome of a rotation drain wait — used by the daemon-side controller
/// to decide whether to proceed straight to swap or proceed-with-timeout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainOutcome {
    /// All in-flight handshakes resolved before the drain window
    /// elapsed. The wrapped value is the in-flight count observed at
    /// the moment drain completed (always zero).
    AllResolved { observed_in_flight: u64 },
    /// The drain window elapsed with `in_flight` handshakes still
    /// outstanding. The rotation MUST still proceed: holding the
    /// rotation open indefinitely would let a stuck peer block
    /// security-relevant operator action.
    Timeout { in_flight: u64 },
}

impl DrainOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            DrainOutcome::AllResolved { .. } => "all_resolved",
            DrainOutcome::Timeout { .. } => "timeout",
        }
    }

    pub fn in_flight(self) -> u64 {
        match self {
            DrainOutcome::AllResolved { observed_in_flight } => observed_in_flight,
            DrainOutcome::Timeout { in_flight } => in_flight,
        }
    }
}

/// Fault-injection point used by the daemon panic-injection test.
/// Disabled in release builds — the daemon flow only consults this when
/// the runtime ledger was constructed with an injection enabled, and the
/// production ledger constructor wires it permanently to `NoFault`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationFaultPoint {
    BeforeKeyWrite,
    BeforeArchive,
    BeforeWatermarkAdvance,
    BeforeWgApply,
    AfterWgApply,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationFault {
    /// Surface as a typed [`RotationError::FaultInjected`] from the
    /// rotation flow. Tests use this to assert atomic rollback paths
    /// without aborting the process.
    Error(RotationFaultPoint),
}

/// One outcome of a rotation attempt. The daemon writes a serialised
/// form of this entry into its audit log so subsequent operator review
/// can reconstruct the rotation timeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationAuditEntry {
    pub epoch_prev: RotationEpoch,
    pub epoch_new: RotationEpoch,
    pub outcome: RotationAuditOutcome,
    pub drain_outcome: Option<DrainOutcome>,
    pub now_unix: u64,
    pub cause: String,
}

impl RotationAuditEntry {
    pub fn success(
        epoch_prev: RotationEpoch,
        epoch_new: RotationEpoch,
        drain_outcome: DrainOutcome,
        now_unix: u64,
    ) -> Self {
        Self {
            epoch_prev,
            epoch_new,
            outcome: RotationAuditOutcome::Success,
            drain_outcome: Some(drain_outcome),
            now_unix,
            cause: "rotation_committed".to_owned(),
        }
    }

    pub fn rollback(
        epoch_prev: RotationEpoch,
        epoch_attempted: RotationEpoch,
        drain_outcome: Option<DrainOutcome>,
        now_unix: u64,
        cause: impl Into<String>,
    ) -> Self {
        Self {
            epoch_prev,
            epoch_new: epoch_attempted,
            outcome: RotationAuditOutcome::Rollback,
            drain_outcome,
            now_unix,
            cause: cause.into(),
        }
    }

    pub fn rejected(epoch_prev: RotationEpoch, now_unix: u64, cause: impl Into<String>) -> Self {
        Self {
            epoch_prev,
            epoch_new: epoch_prev,
            outcome: RotationAuditOutcome::Rejected,
            drain_outcome: None,
            now_unix,
            cause: cause.into(),
        }
    }

    pub fn canonical_line(&self) -> String {
        let drain = self
            .drain_outcome
            .map(|d| d.as_str())
            .unwrap_or("not_attempted");
        let drain_count = self.drain_outcome.map(|d| d.in_flight()).unwrap_or(0);
        format!(
            "ts={} outcome={} epoch_prev={} epoch_new={} drain={} drain_in_flight={} cause={}\n",
            self.now_unix,
            self.outcome.as_str(),
            self.epoch_prev,
            self.epoch_new,
            drain,
            drain_count,
            self.cause,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationAuditOutcome {
    Success,
    Rollback,
    Rejected,
}

impl RotationAuditOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            RotationAuditOutcome::Success => "success",
            RotationAuditOutcome::Rollback => "rollback",
            RotationAuditOutcome::Rejected => "rejected",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotationError {
    AlreadyInProgress {
        state: RotationState,
    },
    EpochOverflow,
    EpochNotMonotonic {
        current: RotationEpoch,
        attempted: RotationEpoch,
    },
    ArchiveDuplicate {
        epoch: RotationEpoch,
    },
    WatermarkDuplicate {
        epoch: RotationEpoch,
    },
    FreezeOnActiveEpoch {
        current: RotationEpoch,
        attempted: RotationEpoch,
    },
    UnknownEpoch {
        epoch: RotationEpoch,
    },
    WatermarkPastRotationPoint {
        epoch: RotationEpoch,
        bundle_watermark: u64,
        freeze_point: u64,
    },
    InvalidStateTransition {
        from: RotationState,
        to: RotationState,
    },
    KeyWriteFailed(String),
    ArchiveWriteFailed(String),
    WatermarkWriteFailed(String),
    BackendApplyFailed(String),
    LedgerCorrupt(String),
    FaultInjected(RotationFaultPoint),
    /// The rotation entered a state from which the daemon cannot
    /// recover without operator intervention. Subsequent rotation
    /// attempts MUST be rejected until the operator resets the state.
    Unrecoverable(String),
}

impl fmt::Display for RotationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RotationError::AlreadyInProgress { state } => {
                write!(f, "rotation already in progress (state={state})")
            }
            RotationError::EpochOverflow => f.write_str("rotation epoch overflowed u64::MAX"),
            RotationError::EpochNotMonotonic { current, attempted } => write!(
                f,
                "rotation epoch not monotonic: current={current} attempted={attempted}"
            ),
            RotationError::ArchiveDuplicate { epoch } => {
                write!(f, "verifier archive already contains epoch {epoch}")
            }
            RotationError::WatermarkDuplicate { epoch } => {
                write!(f, "watermark already frozen for epoch {epoch}")
            }
            RotationError::FreezeOnActiveEpoch { current, attempted } => write!(
                f,
                "cannot freeze the currently-active rotation epoch (current={current} attempted={attempted})"
            ),
            RotationError::UnknownEpoch { epoch } => {
                write!(
                    f,
                    "bundle epoch tag {epoch} is unknown to the watermark store"
                )
            }
            RotationError::WatermarkPastRotationPoint {
                epoch,
                bundle_watermark,
                freeze_point,
            } => write!(
                f,
                "bundle from epoch {epoch} carries watermark {bundle_watermark} which is past the rotation freeze point {freeze_point}"
            ),
            RotationError::InvalidStateTransition { from, to } => {
                write!(f, "invalid rotation state transition {from} -> {to}")
            }
            RotationError::KeyWriteFailed(message) => {
                write!(f, "rotation key write failed: {message}")
            }
            RotationError::ArchiveWriteFailed(message) => {
                write!(f, "rotation archive write failed: {message}")
            }
            RotationError::WatermarkWriteFailed(message) => {
                write!(f, "rotation watermark write failed: {message}")
            }
            RotationError::BackendApplyFailed(message) => {
                write!(f, "rotation backend apply failed: {message}")
            }
            RotationError::LedgerCorrupt(message) => {
                write!(f, "rotation ledger corrupt: {message}")
            }
            RotationError::FaultInjected(point) => {
                write!(f, "rotation fault injected at {point:?}")
            }
            RotationError::Unrecoverable(message) => {
                write!(f, "rotation unrecoverable: {message}")
            }
        }
    }
}

impl std::error::Error for RotationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_epoch_next_increments_monotonically() {
        let genesis = RotationEpoch::GENESIS;
        let next = genesis.next().expect("genesis must increment");
        assert_eq!(next.value(), 1);
        let later = RotationEpoch(42).next().expect("regular increment");
        assert_eq!(later.value(), 43);
    }

    #[test]
    fn rotation_epoch_next_rejects_overflow() {
        let max = RotationEpoch(u64::MAX);
        assert!(matches!(max.next(), Err(RotationError::EpochOverflow)));
    }

    #[test]
    fn rotation_state_transitions_classify_correctly() {
        assert!(RotationState::Idle.is_idle());
        assert!(!RotationState::Draining.is_idle());
        assert!(RotationState::Draining.is_in_progress());
        assert!(RotationState::Swapping.is_in_progress());
        assert!(!RotationState::FailedRollback.is_idle());
    }

    fn verifier(epoch: u64, pubkey: &str, ts: u64, watermark: u64) -> ArchivedVerifier {
        ArchivedVerifier {
            epoch: RotationEpoch(epoch),
            public_key_hex: pubkey.to_owned(),
            archived_at_unix: ts,
            watermark_at_rotation: watermark,
        }
    }

    #[test]
    fn verifier_archive_records_unique_epochs() {
        let mut archive = VerifierArchive::new();
        archive.record(verifier(1, "aa", 100, 7)).expect("first");
        let entry = archive.lookup(RotationEpoch(1)).expect("entry present");
        assert_eq!(entry.public_key_hex, "aa");
        assert_eq!(entry.watermark_at_rotation, 7);
    }

    #[test]
    fn verifier_archive_rejects_duplicate_epoch() {
        let mut archive = VerifierArchive::new();
        archive.record(verifier(1, "aa", 100, 7)).expect("first");
        let err = archive
            .record(verifier(1, "bb", 200, 9))
            .expect_err("duplicate must fail closed");
        assert!(matches!(err, RotationError::ArchiveDuplicate { epoch } if epoch.value() == 1));
    }

    #[test]
    fn verifier_archive_prunes_to_retention_window() {
        let mut archive = VerifierArchive::with_retention(2);
        archive.record(verifier(1, "aa", 100, 1)).expect("first");
        archive.record(verifier(2, "bb", 200, 2)).expect("second");
        archive.record(verifier(3, "cc", 300, 3)).expect("third");
        assert_eq!(archive.len(), 2);
        assert!(archive.lookup(RotationEpoch(1)).is_none());
        assert!(archive.lookup(RotationEpoch(2)).is_some());
        assert!(archive.lookup(RotationEpoch(3)).is_some());
    }

    #[test]
    fn per_epoch_watermark_freezes_outgoing_once() {
        let mut store = PerEpochReplayWatermark::new(RotationEpoch(0));
        store.advance_to(RotationEpoch(1)).expect("advance");
        store
            .freeze_outgoing(RotationEpoch(0), 42)
            .expect("freeze outgoing");
        let err = store
            .freeze_outgoing(RotationEpoch(0), 50)
            .expect_err("duplicate freeze must fail");
        assert!(matches!(err, RotationError::WatermarkDuplicate { epoch } if epoch.value() == 0));
    }

    #[test]
    fn per_epoch_watermark_rejects_freeze_of_active_epoch() {
        let mut store = PerEpochReplayWatermark::new(RotationEpoch(3));
        let err = store
            .freeze_outgoing(RotationEpoch(3), 100)
            .expect_err("cannot freeze active");
        assert!(matches!(
            err,
            RotationError::FreezeOnActiveEpoch { current, attempted }
                if current.value() == 3 && attempted.value() == 3
        ));
    }

    #[test]
    fn per_epoch_watermark_validates_bundle_for_active_epoch() {
        let store = PerEpochReplayWatermark::new(RotationEpoch(5));
        store
            .validate_bundle(RotationEpoch(5), u64::MAX)
            .expect("active epoch always passes");
    }

    #[test]
    fn per_epoch_watermark_rejects_unknown_epoch_in_future() {
        let store = PerEpochReplayWatermark::new(RotationEpoch(2));
        let err = store
            .validate_bundle(RotationEpoch(3), 10)
            .expect_err("future epoch is unknown");
        assert!(matches!(err, RotationError::UnknownEpoch { epoch } if epoch.value() == 3));
    }

    #[test]
    fn per_epoch_watermark_rejects_archived_epoch_past_freeze() {
        let mut store = PerEpochReplayWatermark::new(RotationEpoch(1));
        store.advance_to(RotationEpoch(2)).expect("advance");
        store
            .freeze_outgoing(RotationEpoch(1), 100)
            .expect("freeze outgoing");
        store
            .validate_bundle(RotationEpoch(1), 100)
            .expect("at the freeze point is ok");
        let err = store
            .validate_bundle(RotationEpoch(1), 101)
            .expect_err("past the freeze point must fail closed");
        assert!(matches!(
            err,
            RotationError::WatermarkPastRotationPoint {
                epoch,
                bundle_watermark: 101,
                freeze_point: 100,
            } if epoch.value() == 1
        ));
    }

    #[test]
    fn audit_entry_canonical_line_is_deterministic() {
        let entry = RotationAuditEntry::success(
            RotationEpoch(1),
            RotationEpoch(2),
            DrainOutcome::AllResolved {
                observed_in_flight: 0,
            },
            1_700_000_000,
        );
        let line = entry.canonical_line();
        assert!(line.contains("outcome=success"));
        assert!(line.contains("epoch_prev=1"));
        assert!(line.contains("epoch_new=2"));
        assert!(line.contains("drain=all_resolved"));
    }
}
