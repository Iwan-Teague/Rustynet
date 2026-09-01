#![cfg_attr(not(test), allow(dead_code))]
// offline evaluator core; the live stage `live_signed_state_rollback_replay`, its StageId, runner binary and IPC driving are deferred until the lab is up (design §2.4, §3 precondition 2)
//! Fail-closed report evaluator for the signed-state epoch rollback live
//! stage `live_signed_state_rollback_replay` (GAP-5, design
//! `LiveLabSignedStateRollbackApplyLayerStageDesign_2026-09-01.md` §2.3
//! steps 4-6, adversarial review
//! `LiveLabSignedStateRollbackApplyLayerStageAdversarialReview_2026-09-01.md`
//! §4/§5/§7/§8).
//!
//! The stage replays a genuinely valid previous-epoch membership bundle at a
//! running daemon through the local IPC `membership apply` surface with the
//! admin-role credential, and this evaluator grades the resulting report:
//!
//! - the ordered expected-rejection set is `previous state root mismatch`
//!   (primary, `PrevStateRootMismatch`, `membership.rs:1052-1054`), then
//!   `epoch chain mismatch for membership update` (defensive,
//!   `membership.rs:1055-1059`), then `membership replay detected`
//!   (`ReplayDetected`, `membership.rs:737-742`) — review §4 amendment 1.
//!   `EpochRegression` is NOT in the set: the apply path can never produce it
//!   (`verify_attested_snapshot`, `membership.rs:1513`, is a different
//!   surface), so a report carrying that reason is INCONSISTENT EVIDENCE, a
//!   failure — never a pass.
//! - acceptance (`ipc_response` not a rejection) is the critical failure: the
//!   rollback APPLIED (design §2.3 step 4).
//! - wrong-reason rejections (signature/expiry/future/decode/format) grade
//!   `Blocked`: capture or validity plumbing failed and says nothing about
//!   the control (review §4). A `network id mismatch` rejection is a failure:
//!   the wrong bundle was submitted.
//! - before/after immutability is asserted on every parsed field AND on all
//!   three artifact byte digests (snapshot, watermark, log — review §5).
//! - fail-loud wiring mirrors `AuditVerdict` (`security_audit.rs:104-125`):
//!   `Blocked` is distinct from `Failed` and BOTH fail the stage; a
//!   node-reported skip forces `Skipped` with the node named; a missing or
//!   malformed report is a failure, never a pass (review §7).

use serde::Deserialize;

/// Canonical schema version of the signed-state rollback report.
pub const SIGNED_STATE_ROLLBACK_SCHEMA_VERSION: u64 = 1;

/// The one legitimate delivery surface for the replay (design §2.3 step 3,
/// amendment 2): the daemon's local IPC `membership apply` ingestion entry.
pub const EXPECTED_APPLY_SURFACE: &str = "ipc_membership_apply";

/// The credential role the documented dual gate requires (design §2.3 step 3;
/// role gate at `daemon.rs:36873-36883`).
pub const EXPECTED_CREDENTIAL_ROLE: &str = "admin";

/// Capture provenance for the replayed envelope (design §2.2, amendment 3):
/// SHA-256 pinned at the mint point and re-verified immediately before
/// submission, with the offline validity preconditions.
#[derive(Debug, Clone, Deserialize)]
pub struct SignedStateRollbackCapture {
    /// SHA-256 of the envelope bytes at the moment of capture (mint point).
    pub sha256_at_capture: String,
    /// SHA-256 of the same envelope immediately before submission; a
    /// mismatch with `sha256_at_capture` is capture corruption.
    pub sha256_before_submit: String,
    /// Offline decode of the captured envelope succeeded against the epoch
    /// E-2 state (precondition of §2.2 — a genuinely valid old bundle, not a
    /// malformed-input test).
    pub offline_decode_ok: bool,
    /// Offline signature sanity check of the captured envelope passed
    /// (precondition of §2.2).
    pub signature_sanity_ok: bool,
    /// The envelope's expiry, recorded at capture; the replay is only
    /// submitted while `submitted_at_unix < expires_at_unix`.
    pub expires_at_unix: u64,
    /// The submission timestamp against which the validity window is graded.
    pub submitted_at_unix: u64,
}

/// How the replay was delivered (design §2.3 step 3, amendment 2): only the
/// legitimate apply surface with the admin-role credential exercises the
/// control; anything else is `Blocked`, not evidence.
#[derive(Debug, Clone, Deserialize)]
pub struct SignedStateRollbackSubmission {
    /// Must be [`EXPECTED_APPLY_SURFACE`] — the snapshot-file-drop mechanism
    /// is explicitly forbidden.
    pub surface: String,
    /// Must be [`EXPECTED_CREDENTIAL_ROLE`] — the documented dual gate.
    pub credential_role: String,
}

/// One before/after observation of the daemon under test (design §2.3 step 5,
/// amendment 4): parsed identity fields plus byte digests of the three
/// persisted artifact classes. The parsed persisted field is `state_root`
/// (the `MembershipWatermark` field name), not `max_epoch`.
#[derive(Debug, Clone, Deserialize)]
pub struct SignedStateRollbackObservation {
    /// The daemon's membership epoch (parsed field).
    pub epoch: u64,
    /// The daemon's membership state root (parsed field).
    pub state_root: String,
    /// Byte digest over the attestation identity set (membership view).
    pub attestation_identity_digest: String,
    /// Byte digest of the persisted membership snapshot file.
    pub snapshot_file_digest: String,
    /// Byte digest of the persisted replay-watermark file.
    pub watermark_file_digest: String,
    /// Byte digest of the daemon's membership log artifact.
    pub log_digest: String,
}

/// The report artifact written by the stage runner (design §2.3 step 5).
#[derive(Debug, Clone, Deserialize)]
pub struct SignedStateRollbackReport {
    /// Must equal [`SIGNED_STATE_ROLLBACK_SCHEMA_VERSION`].
    pub schema_version: u64,
    /// Set when the run was a dry run — never evidence, never a pass.
    #[serde(default)]
    pub dry_run: Option<bool>,
    /// Set when the run was explicitly skipped — never evidence, never a pass.
    #[serde(default)]
    pub skipped: Option<bool>,
    /// The node that reported itself skipped, if any; forces `Skipped` with
    /// the node named (review §7, `security_audit.rs:89-96` convention).
    #[serde(default)]
    pub node_reported_skip: Option<String>,
    /// Capture provenance of the replayed envelope.
    pub capture: SignedStateRollbackCapture,
    /// Delivery surface + credential role of the replay.
    pub submission: SignedStateRollbackSubmission,
    /// The verbatim IPC response string (`"membership apply rejected: …"`,
    /// `daemon.rs:9808`).
    pub ipc_response: String,
    /// Pre-replay observation of the daemon.
    pub before: SignedStateRollbackObservation,
    /// Post-replay observation of the daemon.
    pub after: SignedStateRollbackObservation,
}

/// The verdict for the stage, mirroring the `AuditVerdict` fail-loud
/// precedent (`security_audit.rs:106-135`): `Blocked` is deliberately
/// distinct from `Failed` — it means the control was never exercised
/// (capture corruption, validity-window miss, wrong surface/role) — and BOTH
/// fail the stage. Only `Passed` is a pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollbackVerdict {
    /// The rollback was rejected for an attributable reason and every
    /// before/after invariant held.
    Passed,
    /// The control was exercised and violated, or the evidence is
    /// inconsistent (acceptance, drifted state, unattributable reason).
    Failed(String),
    /// The control was never exercised — capture/deliverability problem.
    Blocked(String),
    /// A node reported itself skipped (named in the detail).
    Skipped(String),
}

impl RollbackVerdict {
    /// The run-matrix status string this verdict records. `blocked` outranks
    /// both `skip` and `pass` in the recorder's precedence (`status_rank`),
    /// so an unexercised control can never let a platform read green.
    pub fn matrix_status(&self) -> &'static str {
        match self {
            RollbackVerdict::Passed => "pass",
            RollbackVerdict::Failed(_) => "fail",
            RollbackVerdict::Blocked(_) => "blocked",
            RollbackVerdict::Skipped(_) => "skip",
        }
    }

    pub fn detail(&self) -> Option<&str> {
        match self {
            RollbackVerdict::Passed => None,
            RollbackVerdict::Failed(detail)
            | RollbackVerdict::Blocked(detail)
            | RollbackVerdict::Skipped(detail) => Some(detail.as_str()),
        }
    }

    pub fn is_ok(&self) -> bool {
        matches!(self, RollbackVerdict::Passed)
    }

    /// True for `Failed` AND `Blocked`: both fail the stage (review §7).
    pub fn fails_stage(&self) -> bool {
        matches!(
            self,
            RollbackVerdict::Failed(_) | RollbackVerdict::Blocked(_)
        )
    }
}

/// Fail-closed evaluator for a `live_signed_state_rollback_replay` report
/// (design §2.3 steps 4-6). Rules run in the documented order and every
/// rejection names its reason; an absent, malformed, or wrong-schema report
/// is a FAILURE, never a pass.
pub fn evaluate_signed_state_rollback_report(report_json: &str) -> RollbackVerdict {
    let value: serde_json::Value = match serde_json::from_str(report_json) {
        Ok(value) => value,
        Err(err) => {
            return RollbackVerdict::Failed(format!(
                "signed-state rollback report missing or malformed (never a pass): parse failed: {err}"
            ));
        }
    };
    let schema_version = match value
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
    {
        Some(schema_version) => schema_version,
        None => {
            return RollbackVerdict::Failed(
                "signed-state rollback report missing schema_version; rejecting".to_owned(),
            );
        }
    };
    if schema_version != SIGNED_STATE_ROLLBACK_SCHEMA_VERSION {
        return RollbackVerdict::Failed(format!(
            "signed-state rollback report returned unsupported schema_version={schema_version}"
        ));
    }
    let report: SignedStateRollbackReport = match serde_json::from_value(value) {
        Ok(report) => report,
        Err(err) => {
            return RollbackVerdict::Failed(format!(
                "signed-state rollback report has invalid fields: {err}"
            ));
        }
    };

    // Node-reported skip forces Skipped with the node named (review §7).
    if let Some(node) = report.node_reported_skip.as_deref()
        && !node.trim().is_empty()
    {
        return RollbackVerdict::Skipped(format!("node {node} reported itself skipped"));
    }

    // Dry-run / skipped markers are never evidence.
    if report.dry_run == Some(true) {
        return RollbackVerdict::Failed(
            "signed-state rollback report is a dry run; a dry run is never stage evidence"
                .to_owned(),
        );
    }
    if report.skipped == Some(true) {
        return RollbackVerdict::Failed(
            "signed-state rollback report is marked skipped; a skipped run is never stage evidence"
                .to_owned(),
        );
    }

    // Capture validity (design §2.2, amendment 3): a broken capture says
    // nothing about the control — Blocked, never Failed.
    if report.capture.sha256_at_capture != report.capture.sha256_before_submit {
        return RollbackVerdict::Blocked(format!(
            "captured envelope digest drifted: sha256_at_capture={} sha256_before_submit={}",
            report.capture.sha256_at_capture, report.capture.sha256_before_submit
        ));
    }
    if !report.capture.offline_decode_ok {
        return RollbackVerdict::Blocked(
            "captured envelope failed the offline decode precondition; the control was never exercised".to_owned(),
        );
    }
    if !report.capture.signature_sanity_ok {
        return RollbackVerdict::Blocked(
            "captured envelope failed the offline signature sanity precondition; the control was never exercised".to_owned(),
        );
    }
    if report.capture.submitted_at_unix >= report.capture.expires_at_unix {
        return RollbackVerdict::Blocked(format!(
            "envelope validity window missed: submitted_at_unix={} >= expires_at_unix={}",
            report.capture.submitted_at_unix, report.capture.expires_at_unix
        ));
    }

    // Delivery surface + credential role (design §2.3 step 3, amendment 2):
    // a wrong surface or role means the documented control was never the
    // thing exercised.
    if report.submission.surface != EXPECTED_APPLY_SURFACE {
        return RollbackVerdict::Blocked(format!(
            "replay driven over surface '{}' instead of '{EXPECTED_APPLY_SURFACE}'; the membership apply control was not exercised",
            report.submission.surface
        ));
    }
    if report.submission.credential_role != EXPECTED_CREDENTIAL_ROLE {
        return RollbackVerdict::Blocked(format!(
            "replay driven with credential role '{}' instead of '{EXPECTED_CREDENTIAL_ROLE}'; the role gate refused and the control was not exercised",
            report.submission.credential_role
        ));
    }

    // The rollback MUST have been rejected: anything not starting with the
    // documented rejection prefix is an acceptance — the critical failure.
    const REJECTION_PREFIX: &str = "membership apply rejected:";
    if !report.ipc_response.starts_with(REJECTION_PREFIX) {
        return RollbackVerdict::Failed(format!(
            "CRITICAL: the old-epoch bundle was ACCEPTED, not rejected (ipc_response='{}'); the rollback applied",
            report.ipc_response
        ));
    }

    // Rejection-reason classification on the response text, in the review-§4
    // order: attributable set first, then the inconsistent-evidence case,
    // then wrong-reason plumbing, then wrong-bundle, then unattributable.
    let reason = report.ipc_response.as_str();
    let attributable = [
        "previous state root mismatch",
        "epoch chain mismatch for membership update",
        "membership replay detected",
    ];
    if attributable
        .iter()
        .any(|expected| reason.contains(expected))
    {
        // Attributable: continue to the immutability assertions below.
    } else if reason.contains("epoch regression") {
        return RollbackVerdict::Failed(format!(
            "rejection reason 'epoch regression' is inconsistent evidence: the membership \
             apply path cannot produce EpochRegression (it is constructed only in \
             verify_attested_snapshot, membership.rs:1513), so this response did not come \
             from the surface under test: ipc_response='{reason}'"
        ));
    } else if ["signature", "expired", "future", "decode", "invalid format"]
        .iter()
        .any(|plumbing| reason.contains(plumbing))
    {
        return RollbackVerdict::Blocked(format!(
            "wrong-reason rejection (capture/validity plumbing, not the rollback control): ipc_response='{reason}'"
        ));
    } else if reason.contains("network id mismatch") {
        return RollbackVerdict::Failed(format!(
            "rejection for network id mismatch means the wrong bundle was submitted: ipc_response='{reason}'"
        ));
    } else {
        return RollbackVerdict::Failed(format!(
            "unattributable rejection reason outside the expected set: ipc_response='{reason}'"
        ));
    }

    // Before/after immutability: every parsed field equal AND all three
    // artifact digests equal (design §2.3 step 4, review §5).
    if let Some(drifted) = first_drifted_field(&report.before, &report.after) {
        return RollbackVerdict::Failed(format!(
            "post-replay state drifted at '{drifted}'; a rejected replay must leave the \
             membership view, snapshot, watermark and log byte-identical"
        ));
    }

    RollbackVerdict::Passed
}

/// First drifted before/after field, named for the failure message. Parsed
/// identity fields and all three artifact byte digests participate.
fn first_drifted_field(
    before: &SignedStateRollbackObservation,
    after: &SignedStateRollbackObservation,
) -> Option<String> {
    if before.epoch != after.epoch {
        return Some("epoch".to_owned());
    }
    if before.state_root != after.state_root {
        return Some("state_root".to_owned());
    }
    if before.attestation_identity_digest != after.attestation_identity_digest {
        return Some("attestation_identity_digest".to_owned());
    }
    if before.snapshot_file_digest != after.snapshot_file_digest {
        return Some("snapshot_file_digest".to_owned());
    }
    if before.watermark_file_digest != after.watermark_file_digest {
        return Some("watermark_file_digest".to_owned());
    }
    if before.log_digest != after.log_digest {
        return Some("log_digest".to_owned());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const REJECTED_PRIMARY: &str = "membership apply rejected: previous state root mismatch";

    /// The fully passing report: genuine rejection at the primary guard,
    /// clean capture, correct surface/role, untouched before/after state.
    fn passing_report() -> serde_json::Value {
        json!({
            "schema_version": 1,
            "dry_run": false,
            "skipped": false,
            "node_reported_skip": null,
            "capture": {
                "sha256_at_capture": "aa".repeat(32),
                "sha256_before_submit": "aa".repeat(32),
                "offline_decode_ok": true,
                "signature_sanity_ok": true,
                "expires_at_unix": 1000,
                "submitted_at_unix": 900,
            },
            "submission": {
                "surface": "ipc_membership_apply",
                "credential_role": "admin",
            },
            "ipc_response": REJECTED_PRIMARY,
            "before": observation(7, "root-7", "att-7", "snap-7", "wm-7", "log-7"),
            "after": observation(7, "root-7", "att-7", "snap-7", "wm-7", "log-7"),
        })
    }

    fn observation(
        epoch: u64,
        state_root: &str,
        attestation: &str,
        snapshot: &str,
        watermark: &str,
        log: &str,
    ) -> serde_json::Value {
        json!({
            "epoch": epoch,
            "state_root": state_root,
            "attestation_identity_digest": attestation,
            "snapshot_file_digest": snapshot,
            "watermark_file_digest": watermark,
            "log_digest": log,
        })
    }

    fn verdict_for(report: serde_json::Value) -> RollbackVerdict {
        evaluate_signed_state_rollback_report(&report.to_string())
    }

    fn assert_blocked(verdict: RollbackVerdict, needle: &str) {
        match &verdict {
            RollbackVerdict::Blocked(detail) => assert!(
                detail.contains(needle),
                "blocked detail must name '{needle}', got: {detail}"
            ),
            other => panic!("expected Blocked naming '{needle}', got {other:?}"),
        }
    }

    fn assert_failed(verdict: RollbackVerdict, needle: &str) {
        match &verdict {
            RollbackVerdict::Failed(detail) => assert!(
                detail.contains(needle),
                "failed detail must name '{needle}', got: {detail}"
            ),
            other => panic!("expected Failed naming '{needle}', got {other:?}"),
        }
    }

    #[test]
    fn genuine_primary_rejection_passes() {
        assert_eq!(verdict_for(passing_report()), RollbackVerdict::Passed);
    }

    #[test]
    fn defensive_epoch_chain_rejection_passes() {
        let mut report = passing_report();
        report["ipc_response"] =
            json!("membership apply rejected: epoch chain mismatch for membership update");
        assert_eq!(verdict_for(report), RollbackVerdict::Passed);
    }

    #[test]
    fn replay_detected_rejection_passes() {
        let mut report = passing_report();
        report["ipc_response"] = json!("membership apply rejected: membership replay detected");
        assert_eq!(verdict_for(report), RollbackVerdict::Passed);
    }

    #[test]
    fn acceptance_is_the_critical_failure() {
        let mut report = passing_report();
        report["ipc_response"] = json!("membership apply accepted: epoch=8");
        assert_failed(
            verdict_for(report),
            "CRITICAL: the old-epoch bundle was ACCEPTED",
        );
    }

    #[test]
    fn capture_digest_mismatch_blocks() {
        let mut report = passing_report();
        report["capture"]["sha256_before_submit"] = json!("bb".repeat(32));
        assert_blocked(verdict_for(report), "digest drifted");
    }

    #[test]
    fn offline_decode_failure_blocks() {
        let mut report = passing_report();
        report["capture"]["offline_decode_ok"] = json!(false);
        assert_blocked(verdict_for(report), "offline decode precondition");
    }

    #[test]
    fn signature_sanity_failure_blocks() {
        let mut report = passing_report();
        report["capture"]["signature_sanity_ok"] = json!(false);
        assert_blocked(verdict_for(report), "signature sanity precondition");
    }

    #[test]
    fn expired_validity_window_blocks() {
        let mut report = passing_report();
        report["capture"]["submitted_at_unix"] = json!(1000);
        assert_blocked(verdict_for(report), "validity window missed");
    }

    #[test]
    fn wrong_surface_blocks() {
        let mut report = passing_report();
        report["submission"]["surface"] = json!("snapshot_file_drop");
        assert_blocked(verdict_for(report), "was not exercised");
    }

    #[test]
    fn wrong_credential_role_blocks() {
        let mut report = passing_report();
        report["submission"]["credential_role"] = json!("client");
        assert_blocked(verdict_for(report), "role gate refused");
    }

    #[test]
    fn epoch_regression_reason_is_inconsistent_evidence() {
        let mut report = passing_report();
        report["ipc_response"] =
            json!("membership apply rejected: membership epoch regression: offered epoch 2");
        assert_failed(verdict_for(report), "cannot produce EpochRegression");
    }

    #[test]
    fn signature_rejection_reason_blocks_as_wrong_reason() {
        let mut report = passing_report();
        report["ipc_response"] = json!("membership apply rejected: signature invalid");
        assert_blocked(verdict_for(report), "capture/validity plumbing");
    }

    #[test]
    fn network_id_rejection_is_a_failure() {
        let mut report = passing_report();
        report["ipc_response"] =
            json!("membership apply rejected: network id mismatch in membership update");
        assert_failed(verdict_for(report), "wrong bundle was submitted");
    }

    #[test]
    fn unattributable_reason_fails() {
        let mut report = passing_report();
        report["ipc_response"] = json!("membership apply rejected: quorum floor lowered");
        assert_failed(verdict_for(report), "unattributable rejection reason");
    }

    #[test]
    fn every_drifted_field_fails_by_name() {
        let fields = [
            ("epoch", json!(8)),
            ("state_root", json!("root-8")),
            ("attestation_identity_digest", json!("att-8")),
            ("snapshot_file_digest", json!("snap-8")),
            ("watermark_file_digest", json!("wm-8")),
            ("log_digest", json!("log-8")),
        ];
        for (field, value) in fields {
            let mut report = passing_report();
            report["after"][field] = value;
            let verdict = verdict_for(report);
            match &verdict {
                RollbackVerdict::Failed(detail) => assert!(
                    detail.contains(field),
                    "failure must name the drifted field '{field}', got: {detail}"
                ),
                other => panic!("drifted {field}: expected Failed, got {other:?}"),
            }
        }
    }

    #[test]
    fn node_reported_skip_is_skipped_naming_the_node() {
        let mut report = passing_report();
        report["node_reported_skip"] = json!("windows-node-1");
        match verdict_for(report) {
            RollbackVerdict::Skipped(detail) => {
                assert!(
                    detail.contains("windows-node-1"),
                    "node named, got: {detail}"
                );
            }
            other => panic!("expected Skipped, got {other:?}"),
        }
    }

    #[test]
    fn dry_run_is_a_failure() {
        let mut report = passing_report();
        report["dry_run"] = json!(true);
        assert_failed(verdict_for(report), "dry run");
    }

    #[test]
    fn skipped_marker_is_a_failure() {
        let mut report = passing_report();
        report["skipped"] = json!(true);
        assert_failed(verdict_for(report), "marked skipped");
    }

    #[test]
    fn malformed_json_is_a_failure() {
        assert_failed(
            evaluate_signed_state_rollback_report("{not json"),
            "missing or malformed",
        );
    }

    #[test]
    fn empty_report_is_a_failure() {
        assert_failed(
            evaluate_signed_state_rollback_report(""),
            "missing or malformed",
        );
    }

    #[test]
    fn wrong_schema_version_is_a_failure() {
        let mut report = passing_report();
        report["schema_version"] = json!(2);
        assert_failed(verdict_for(report), "unsupported schema_version=2");
    }

    #[test]
    fn verdict_mapping_blocked_fails_the_stage() {
        assert_eq!(RollbackVerdict::Passed.matrix_status(), "pass");
        assert_eq!(RollbackVerdict::Failed("x".into()).matrix_status(), "fail");
        assert_eq!(
            RollbackVerdict::Blocked("x".into()).matrix_status(),
            "blocked"
        );
        assert_eq!(RollbackVerdict::Skipped("x".into()).matrix_status(), "skip");

        assert!(RollbackVerdict::Passed.is_ok());
        assert!(!RollbackVerdict::Passed.fails_stage());
        assert!(RollbackVerdict::Failed("x".into()).fails_stage());
        assert!(RollbackVerdict::Blocked("x".into()).fails_stage());
        assert!(!RollbackVerdict::Skipped("x".into()).fails_stage());
        assert!(RollbackVerdict::Passed.detail().is_none());
        assert_eq!(RollbackVerdict::Failed("x".into()).detail(), Some("x"));
    }
}
