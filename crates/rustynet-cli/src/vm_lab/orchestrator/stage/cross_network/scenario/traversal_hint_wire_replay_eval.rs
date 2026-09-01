#![cfg_attr(not(test), allow(dead_code))]
// offline core; the live stage wiring + the A8 validator-side host capability
// land when the lab is up (GAP-4 §2.6/§5, design amendment A8)
//! Offline core of GAP-4: the traversal-hint bundle-path replay stage's
//! fixture guard and fail-closed report evaluator, per design
//! `documents/operations/active/LiveLabTraversalHintWireReplayStageDesign_2026-09-01.md`
//! (§2/A1-A8, §3.3 checks table, §4 offline test list) and its adversarial
//! review (`LiveLabTraversalHintWireReplayStageAdversarialReview_2026-09-01.md`).
//!
//! What the stage must prove: an old but validly-signed traversal-hint
//! bundle, replayed into the node's REAL bundle path with a FORCED refresh
//! during an established session, cannot move that session's endpoint —
//! because the bundle-load watermark/anti-rollback layer rejects it
//! (daemon.rs:15486-15501, surfaced as `ReplayDetected` at daemon.rs:5902-5910;
//! `TraversalWatermark { generated_at_unix, nonce, payload_digest }` at
//! daemon.rs:15481-15485), while the in-envelope
//! `validate_signed_coordination_record` (traversal.rs:1466-1511) is only the
//! secondary layer (A1).
//!
//! This module is an evaluator over *recorded* evidence: no I/O, no adapter
//! calls, no lab, no rustynetd import — the daemon behaviors above are cited
//! by line, not linked. The live wiring (injector on a non-coordinator node,
//! bundle-path file delivery, forced refresh, teardown/restore per A6) plus
//! the A8 host capability for reading receiver-side persisted watermark state
//! are deferred until the lab is up; until then this module's only execution
//! is the `#[cfg(test)]` suite below.
//!
//! Daemon facts the guards mirror, with the review's corrected citations:
//! - hints load FROM DISK via `load_traversal_bundle_set` inside
//!   `refresh_traversal_hint_state` (daemon.rs:5856-5937, load at 5874-5880);
//!   the bundle file itself is delivered by `state_fetcher.fetch_traversal()`
//!   inside `refresh_signed_state_with_reason` (daemon.rs:5949-5953) — the
//!   fetch race that can overwrite an injected bundle (A4c).
//! - the single-snapshot contract (daemon.rs:15455-15463, duplicate-pair
//!   reject at 15472-15477): a mangled fixture yields `InvalidFormat`, not
//!   `ReplayDetected` (§2.2), so a torn fixture must never read as a pass.
//! - `traversal_hints` / `traversal_hint_error` state (daemon.rs:4701/4707):
//!   the error is set on every failure path (load 5866-5872, persist
//!   5884-5889, ReplayDetected/Stale/InvalidFormat 5902-5910) and CLEARED on
//!   a successful refresh (5892) — the evidence-evaporation hazard (§2.3).
//! - refresh trigger call sites the evaluator accepts as attributable:
//!   daemon.rs:6015, 8755, 8882, 8993, 9220, 10375 (any non-empty label).
//!
//! Fail-closed throughout: a missing/unparseable report, a dry-run or skipped
//! marker, an incomplete soak (A7), an injector on the coordinator, a silent
//! drop, an unobserved refresh trigger, a lost fetch race, or a correlation
//! mismatch is a named failure — never an absent-and-ignored pass (§2.3,
//! §2.7, §3.3).

use serde::Deserialize;
use std::cmp::Ordering;

/// Canonical schema version of the wire-replay stage report. Pinned: an
/// evaluator must refuse a report written against a different contract.
pub const TRAVERSAL_HINT_WIRE_REPLAY_SCHEMA_VERSION: u64 = 1;

// ── A3: fixture guard ────────────────────────────────────────────────────────

/// The three-part traversal watermark, mirroring the daemon's
/// `TraversalWatermark` (daemon.rs:15481-15485). Ordering below mirrors the
/// anti-rollback check (daemon.rs:15486-15501).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Watermark {
    pub generated_at_unix: u64,
    pub nonce: String,
    pub payload_digest: String,
}

impl Watermark {
    /// True when a bundle carrying `self` must be REJECTED against the live
    /// (persisted) watermark, mirroring the daemon's anti-rollback semantics
    /// (daemon.rs:15486-15501, surfaced as `ReplayDetected` at 5902-5910):
    /// The daemon orders watermarks by `generated_at_unix`, then by `nonce`
    /// (`traversal_watermark_ordering`, daemon.rs:16523-16531):
    /// - orders `Less` than persisted ⇒ rejected (rollback/replay);
    /// - orders `Equal` (same generation AND same nonce) with a DIFFERENT
    ///   `payload_digest` ⇒ rejected (same snapshot identity, divergent
    ///   content);
    /// - `Equal` with the same digest ⇒ the current bundle, not a replay;
    /// - orders `Greater` ⇒ not a replay by this layer.
    pub fn is_replay_of(&self, live: &Watermark) -> bool {
        match self.ordering_against(live) {
            Ordering::Less => true,
            Ordering::Equal => self.payload_digest != live.payload_digest,
            Ordering::Greater => false,
        }
    }

    /// The daemon's watermark ordering (`traversal_watermark_ordering`,
    /// daemon.rs:16523-16531): generation first, nonce as the tiebreak.
    pub fn ordering_against(&self, other: &Watermark) -> Ordering {
        self.generated_at_unix
            .cmp(&other.generated_at_unix)
            .then(self.nonce.cmp(&other.nonce))
    }
}

/// Correlation identity of a replay fixture (A3): the nonce and payload
/// digest of the injected envelope. The report evaluator only credits a
/// rejection that correlates to BOTH.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelationId {
    pub nonce: String,
    pub payload_digest: String,
}

/// One replay fixture as captured from the node's bundle path (§2.2: there
/// is no wire capture point — the capture vantage is the bundle file, and
/// nonce consumption is only sound when derived from the receiver-side
/// persisted watermark state, the A8 capability).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayFixture {
    /// The in-envelope signature verified (secondary layer,
    /// traversal.rs:1466-1511). An invalid signature is an InvalidFormat
    /// rejection, not evidence of replay rejection.
    pub signature_valid: bool,
    /// The watermark carried by the injected (old) envelope.
    pub envelope_watermark: Watermark,
    /// The receiver's current persisted watermark.
    pub live_watermark: Watermark,
    /// Derived from the receiver's persisted watermark state (A8), not from
    /// the injector's own bookkeeping.
    pub nonce_consumed_by_receiver: bool,
    /// The single-snapshot contract intact (daemon.rs:15455-15463): a torn
    /// fixture yields InvalidFormat and must not be scored as a replay pass.
    pub single_snapshot: bool,
    /// Envelope expiry on the DAEMON's clock (A5).
    pub envelope_expires_at_unix: u64,
    /// Daemon-observed `now_unix` at capture (A5).
    pub daemon_now_unix_at_capture: u64,
}

/// Why [`validate_replay_fixture`] refused the fixture. Every refusal is a
/// defect in the STAGE FIXTURE, never a scoring pass: a fixture that the
/// daemon would reject for a non-replay reason (bad signature, torn
/// snapshot, expired-at-capture) cannot attribute a `ReplayDetected` result
/// to the replay (§2.2, A3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixtureRefusal {
    /// The envelope signature does not verify.
    SignatureInvalid,
    /// The receiver's persisted watermark state does not show the nonce as
    /// consumed — the replay precondition is not established.
    NonceNotConsumedByReceiver,
    /// The envelope watermark is NOT strictly older than the live watermark:
    /// equal-with-same-digest is the current bundle, and a newer envelope is
    /// future-dated — neither is a replay sample.
    EnvelopeWatermarkNotStrictlyOlder,
    /// The single-snapshot contract is not intact; the daemon would emit
    /// `InvalidFormat` (daemon.rs:15455-15463), which never scores as a pass.
    SnapshotNotSingle,
    /// The envelope was already expired at capture on the DAEMON's clock
    /// (A5): the daemon would reject it as stale before any watermark check.
    ExpiredAtCapture,
}

impl FixtureRefusal {
    pub fn reason(&self) -> &'static str {
        match self {
            FixtureRefusal::SignatureInvalid => "envelope signature invalid",
            FixtureRefusal::NonceNotConsumedByReceiver => "nonce not consumed by receiver",
            FixtureRefusal::EnvelopeWatermarkNotStrictlyOlder => {
                "envelope watermark not strictly older than live watermark"
            }
            FixtureRefusal::SnapshotNotSingle => "single-snapshot contract not intact",
            FixtureRefusal::ExpiredAtCapture => "envelope already expired at capture",
        }
    }
}

/// Validate a replay fixture before it is ever injected (A3). Returns the
/// fixture's correlation identity on success; every refusal names the
/// reason. Order matters: identity/trust preconditions first, then the
/// watermark precondition, then the snapshot and daemon-clock freshness
/// preconditions — a fixture must fail its EARLIEST violated precondition
/// so the report cannot mask it behind a later rejection class.
pub fn validate_replay_fixture(fixture: &ReplayFixture) -> Result<CorrelationId, FixtureRefusal> {
    if !fixture.signature_valid {
        return Err(FixtureRefusal::SignatureInvalid);
    }
    if !fixture.nonce_consumed_by_receiver {
        return Err(FixtureRefusal::NonceNotConsumedByReceiver);
    }
    // `Watermark::is_replay_of` tells us whether the daemon WOULD reject the
    // envelope — the experiment's intent — but the fixture precondition is
    // stricter than "would be rejected": equal-same-digest is the current
    // bundle and newer is future-dated (neither is a replay), and
    // equal-different-digest is a divergence sample, not an OLD bundle. So
    // the guard requires a strictly older generation outright (A3: "envelope
    // watermark asserted older than live").
    let strictly_older =
        fixture.envelope_watermark.generated_at_unix < fixture.live_watermark.generated_at_unix;
    if !strictly_older {
        return Err(FixtureRefusal::EnvelopeWatermarkNotStrictlyOlder);
    }
    if !fixture.single_snapshot {
        return Err(FixtureRefusal::SnapshotNotSingle);
    }
    if fixture.envelope_expires_at_unix <= fixture.daemon_now_unix_at_capture {
        return Err(FixtureRefusal::ExpiredAtCapture);
    }
    Ok(CorrelationId {
        nonce: fixture.envelope_watermark.nonce.clone(),
        payload_digest: fixture.envelope_watermark.payload_digest.clone(),
    })
}

// ── §3.3: report evaluator ──────────────────────────────────────────────────

/// The observed forced-refresh trigger (A4a). Attributable only when the
/// refresh was actually observed post-injection AND carries a non-empty
/// call-site label (the daemon's hint-refresh call sites: daemon.rs:6015,
/// 8755, 8882, 8993, 9220, 10375 — any non-empty label accepted; the exact
/// site may drift with the daemon, the OBSERVATION may not).
#[derive(Debug, Clone, Deserialize)]
pub struct WireReplayRefreshTrigger {
    pub observed: bool,
    #[serde(default)]
    pub call_site: Option<String>,
}

/// The rejection the daemon recorded (A4b). Only a record whose nonce AND
/// payload digest correlate to the injected fixture can attribute the
/// rejection to the replay.
#[derive(Debug, Clone, Deserialize)]
pub struct WireReplayRejectionRecord {
    /// `replay_detected` | `watermark` | `generation` | `stale` |
    /// `invalid_format` | other (others are unattributable).
    pub reason_class: String,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub payload_digest: Option<String>,
    /// Daemon-observed clock at injection (A5); recorded evidence.
    #[serde(default)]
    pub daemon_now_unix_at_injection: Option<u64>,
}

/// One node's session endpoint pair, before and after the replay attempt.
/// The endpoint pair must be byte-identical across the replay (§3.3
/// `session_endpoint_immovable`).
#[derive(Debug, Clone, Deserialize)]
pub struct WireReplayNodeEndpoints {
    #[serde(default)]
    pub node: Option<String>,
    pub endpoint_pair_baseline: String,
    pub endpoint_pair_after: String,
}

/// The wire-replay stage report, deserialized strictly against the pinned
/// schema ([`TRAVERSAL_HINT_WIRE_REPLAY_SCHEMA_VERSION`]). Optional markers
/// (`dry_run`, `skipped`) are absent-by-default and FAIL when present-true —
/// an absent marker cannot smuggle a pass, a present-true marker cannot
/// hide one (§3.3).
#[derive(Debug, Clone, Deserialize)]
pub struct WireReplayReport {
    pub schema_version: u64,
    #[serde(default)]
    pub dry_run: Option<bool>,
    #[serde(default)]
    pub skipped: Option<bool>,
    /// A7: an incomplete soak means the validator did not survive to the
    /// assertion window; a partial report must never read as a narrow pass.
    pub soak_complete: bool,
    pub refresh_trigger: WireReplayRefreshTrigger,
    /// `"won"` | `"lost"` — whether the injected bundle survived the
    /// `state_fetcher.fetch_traversal()` race (daemon.rs:5949-5953, A4c).
    pub fetch_race: String,
    #[serde(default)]
    pub rejection_record: Option<WireReplayRejectionRecord>,
    /// BOTH session nodes' endpoint pairs (§3.3). A report covering fewer
    /// than two nodes lacks the immovability evidence and fails closed.
    pub nodes: Vec<WireReplayNodeEndpoints>,
    pub hint_generation_baseline: u64,
    pub hint_generation_after: u64,
    pub session_liveness_during: bool,
    pub session_liveness_after: bool,
    pub envelope_expires_at_unix: u64,
    pub daemon_now_unix_at_capture: u64,
    /// A2 vantage assertion: the injector must NOT run on the coordinator.
    pub injector_ran_on_coordinator: bool,
    /// A2 vantage assertion: delivery must be via the node's REAL bundle
    /// path, not a control-plane shortcut.
    pub delivered_via_real_bundle_path: bool,
}

/// Fail-closed evaluator for the wire-replay stage report (design §3.3,
/// §4). Returns a summary naming every earned check, or a named failure.
///
/// Preconditions (each a hard Err): the report string is present and parses
/// as JSON; `schema_version` is present and equals
/// [`TRAVERSAL_HINT_WIRE_REPLAY_SCHEMA_VERSION`]; no dry-run or skipped
/// marker; `soak_complete` (A7); the injector ran OFF the coordinator;
/// delivery went via the real bundle path.
///
/// The four §3.3 checks are EARNED, never defaulted:
/// - `wire_replay_rejected`: refresh observed with a non-empty call site,
///   fetch race WON, a rejection record correlated to `expected` (nonce AND
///   payload digest), and an attributable reason class — `replay_detected`
///   / `watermark` / `generation` outright, `stale` only when the envelope
///   was within TTL at capture on the daemon clock (A5);
///   `invalid_format` NEVER passes (§2.2). A silent drop, an unobserved
///   refresh, or a lost fetch race is an unattributable failure.
/// - `session_endpoint_immovable`: BOTH nodes' endpoint pairs byte-identical
///   to baseline; a moved endpoint fails the whole report.
/// - `hint_generation_stable`: generation never bumps across the replay.
/// - `session_survives_replay`: liveness held during AND after.
pub fn evaluate_wire_replay_report(
    report_json: &str,
    expected: &CorrelationId,
) -> Result<String, String> {
    if report_json.trim().is_empty() {
        return Err(
            "wire-replay report missing or empty; a stage that never produced a report is a \
             FAILED stage, never a skip (§3.3)"
                .to_owned(),
        );
    }
    let value: serde_json::Value = serde_json::from_str(report_json)
        .map_err(|err| format!("parse wire-replay report JSON failed: {err}"))?;
    let schema_field = value
        .get("schema_version")
        .ok_or_else(|| "wire-replay report missing schema_version; rejecting".to_owned())?;
    let schema_version = schema_field.as_u64().ok_or_else(|| {
        format!("wire-replay report schema_version is not an unsigned integer: {schema_field}")
    })?;
    if schema_version != TRAVERSAL_HINT_WIRE_REPLAY_SCHEMA_VERSION {
        return Err(format!(
            "wire-replay report returned unsupported schema_version={schema_version}"
        ));
    }
    let report: WireReplayReport = serde_json::from_value(value)
        .map_err(|err| format!("wire-replay report has invalid fields: {err}"))?;

    if report.dry_run == Some(true) {
        return Err(
            "wire-replay stage ran with a dry_run marker; a dry run cannot pass a live \
             replay-rejection check"
                .to_owned(),
        );
    }
    if report.skipped == Some(true) {
        return Err(
            "wire-replay stage reports skipped injection; a skipped stage is failed, never \
             absent-and-ignored (§3.3)"
                .to_owned(),
        );
    }
    if !report.soak_complete {
        return Err(
            "wire-replay soak incomplete (A7): the validator failed mid-soak or never \
             reached the assertion window; a partial report must not read as a narrow pass"
                .to_owned(),
        );
    }
    if report.injector_ran_on_coordinator {
        return Err(
            "vantage violated (A2): injector ran on the coordinator node; the replay \
             vantage requires injection from a non-coordinator peer"
                .to_owned(),
        );
    }
    if !report.delivered_via_real_bundle_path {
        return Err(
            "vantage violated (A2): envelope was not delivered via the node's real bundle \
             path; a control-plane shortcut proves nothing about bundle-load rejection"
                .to_owned(),
        );
    }

    let mut failures: Vec<String> = Vec::new();

    // Check 1: wire_replay_rejected — earned only through an attributable,
    // observed rejection chain.
    match wire_replay_rejected_failure(&report, expected) {
        Ok(()) => {}
        Err(reason) => failures.push(reason),
    }

    // Check 2: session_endpoint_immovable — BOTH nodes byte-identical.
    if report.nodes.len() < 2 {
        failures.push(format!(
            "session_endpoint_immovable FAILED: endpoint evidence covers {} node(s), the \
             two-node session contract requires both",
            report.nodes.len()
        ));
    } else {
        for node in &report.nodes {
            if node.endpoint_pair_baseline != node.endpoint_pair_after {
                failures.push(format!(
                    "session_endpoint_immovable FAILED: node {:?} endpoint pair moved \
                     across the replay (baseline {:?} -> after {:?}); a moved endpoint \
                     fails the whole report",
                    node.node, node.endpoint_pair_baseline, node.endpoint_pair_after,
                ));
            }
        }
    }

    // Check 3: hint_generation_stable — the hint generation never bumps on a
    // rejected replay.
    if report.hint_generation_after != report.hint_generation_baseline {
        failures.push(format!(
            "hint_generation_stable FAILED: hint generation bumped {} -> {} across the \
             replay; a rejected replay must not mutate generation state",
            report.hint_generation_baseline, report.hint_generation_after,
        ));
    }

    // Check 4: session_survives_replay — liveness during AND after.
    if !report.session_liveness_during || !report.session_liveness_after {
        failures.push(format!(
            "session_survives_replay FAILED: liveness during={} after={}; the session \
             must hold through the replay attempt and after it",
            report.session_liveness_during, report.session_liveness_after,
        ));
    }

    if !failures.is_empty() {
        return Err(failures.join("; "));
    }

    Ok(format!(
        "wire-replay verified: wire_replay_rejected ({} rejection correlated to nonce+digest), \
         session_endpoint_immovable ({}/{} nodes byte-identical), hint_generation_stable ({}), \
         session_survives_replay",
        report
            .rejection_record
            .as_ref()
            .map(|record| record.reason_class.as_str())
            .unwrap_or("?"),
        report
            .nodes
            .iter()
            .filter(|node| node.endpoint_pair_baseline == node.endpoint_pair_after)
            .count(),
        report.nodes.len(),
        report.hint_generation_after,
    ))
}

/// The earned-ness logic of the `wire_replay_rejected` check (A4, §2.2,
/// §2.3). A silent drop, an unobserved refresh, a lost fetch race, a
/// correlation mismatch, or an unattributable reason class is a FAILURE —
/// the absence of a rejection record is never a pass.
fn wire_replay_rejected_failure(
    report: &WireReplayReport,
    expected: &CorrelationId,
) -> Result<(), String> {
    if !report.refresh_trigger.observed {
        return Err(
            "wire_replay_rejected UNATTRIBUTABLE: forced refresh was never observed after \
             injection; without the refresh trigger the injected bundle was never loaded, \
             so a silent drop cannot be distinguished from a rejection (§2.3)"
                .to_owned(),
        );
    }
    let call_site = report.refresh_trigger.call_site.as_deref();
    match call_site {
        Some(site) if !site.trim().is_empty() => {}
        _ => {
            return Err(
                "wire_replay_rejected UNATTRIBUTABLE: refresh observed without a call-site \
                 label; the load cannot be attributed to a real hint-refresh path (A4a)"
                    .to_owned(),
            );
        }
    }
    if report.fetch_race != "won" {
        return Err(format!(
            "wire_replay_rejected UNATTRIBUTABLE: fetch race {} (state_fetcher.fetch_traversal \
             may have overwritten the injected bundle, daemon.rs:5949-5953); a lost race \
             proves nothing about watermark rejection (A4c)",
            report.fetch_race,
        ));
    }
    let record = match &report.rejection_record {
        Some(record) => record,
        None => {
            return Err(
                "wire_replay_rejected FAILED: no rejection recorded despite an observed, \
                 race-won refresh — the replayed bundle was accepted, not rejected"
                    .to_owned(),
            );
        }
    };
    if record.nonce.as_deref() != Some(expected.nonce.as_str())
        || record.payload_digest.as_deref() != Some(expected.payload_digest.as_str())
    {
        return Err(format!(
            "wire_replay_rejected UNATTRIBUTABLE: recorded rejection (nonce={:?}, \
             digest={:?}) does not correlate to the injected fixture (nonce={:?}, \
             digest={:?}); the rejection may belong to another stimulus",
            record.nonce, record.payload_digest, expected.nonce, expected.payload_digest,
        ));
    }
    match record.reason_class.as_str() {
        "replay_detected" | "watermark" | "generation" => Ok(()),
        "invalid_format" => Err(
            "wire_replay_rejected NOT EARNED: rejection class invalid_format means the \
             fixture was mangled, not replay-rejected (§2.2); a mangled fixture can never \
             score as a replay pass"
                .to_owned(),
        ),
        "stale" => {
            // A5: a staleness rejection only counts when the envelope was
            // actually within TTL at capture on the DAEMON's clock —
            // otherwise the daemon rejected an already-dead envelope and
            // proved nothing about replay handling.
            if report.envelope_expires_at_unix > report.daemon_now_unix_at_capture {
                Ok(())
            } else {
                Err(
                    "wire_replay_rejected NOT EARNED: staleness rejection without daemon-\
                     clock TTL evidence — the envelope was already expired at capture, so \
                     the stale rejection is not attributable to replay handling (A5)"
                        .to_owned(),
                )
            }
        }
        other => Err(format!(
            "wire_replay_rejected UNATTRIBUTABLE: unknown rejection reason_class '{other}'"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Fixture builders ─────────────────────────────────────────────────────

    /// An all-good fixture: signed, nonce consumed, envelope strictly older
    /// than live, single snapshot, within TTL at capture on the daemon clock.
    fn good_fixture() -> ReplayFixture {
        ReplayFixture {
            signature_valid: true,
            envelope_watermark: Watermark {
                generated_at_unix: 1000,
                nonce: "nonce-old".to_owned(),
                payload_digest: "digest-old".to_owned(),
            },
            live_watermark: Watermark {
                generated_at_unix: 2000,
                nonce: "nonce-live".to_owned(),
                payload_digest: "digest-live".to_owned(),
            },
            nonce_consumed_by_receiver: true,
            single_snapshot: true,
            envelope_expires_at_unix: 5000,
            daemon_now_unix_at_capture: 4000,
        }
    }

    fn expected_correlation() -> CorrelationId {
        CorrelationId {
            nonce: "nonce-old".to_owned(),
            payload_digest: "digest-old".to_owned(),
        }
    }

    // ── Report builder: one all-good fixture + per-test mutations ────────────

    fn endpoint_pair(node: &str, direction: &str) -> String {
        format!("{node}:51820<->{direction}:51820")
    }

    fn good_report() -> serde_json::Value {
        serde_json::json!({
            "schema_version": TRAVERSAL_HINT_WIRE_REPLAY_SCHEMA_VERSION,
            "dry_run": false,
            "skipped": false,
            "soak_complete": true,
            "refresh_trigger": {
                "observed": true,
                "call_site": "daemon.rs:6015",
            },
            "fetch_race": "won",
            "rejection_record": {
                "reason_class": "watermark",
                "nonce": "nonce-old",
                "payload_digest": "digest-old",
                "daemon_now_unix_at_injection": 4100,
            },
            "nodes": [
                {
                    "node": "client-1",
                    "endpoint_pair_baseline": endpoint_pair("10.0.0.2", "10.0.0.1"),
                    "endpoint_pair_after": endpoint_pair("10.0.0.2", "10.0.0.1"),
                },
                {
                    "node": "exit-1",
                    "endpoint_pair_baseline": endpoint_pair("10.0.0.1", "10.0.0.2"),
                    "endpoint_pair_after": endpoint_pair("10.0.0.1", "10.0.0.2"),
                },
            ],
            "hint_generation_baseline": 7,
            "hint_generation_after": 7,
            "session_liveness_during": true,
            "session_liveness_after": true,
            "envelope_expires_at_unix": 5000,
            "daemon_now_unix_at_capture": 4000,
            "injector_ran_on_coordinator": false,
            "delivered_via_real_bundle_path": true,
        })
    }

    fn evaluate_good() -> Result<String, String> {
        evaluate_wire_replay_report(&good_report().to_string(), &expected_correlation())
    }

    // ── Design §4: the eight offline tests ───────────────────────────────────

    /// §4 test 1: a report with no rejection record fails — the daemon
    /// accepting the replayed bundle is the vulnerability, and absence of a
    /// rejection is never a pass.
    #[test]
    fn wire_replay_report_without_rejection_record_fails() {
        let mut report = good_report();
        report["rejection_record"] = serde_json::json!(null);
        let err = evaluate_wire_replay_report(&report.to_string(), &expected_correlation())
            .expect_err("a report without a rejection record must fail");
        assert!(
            err.contains("no rejection recorded"),
            "should name the missing rejection, got: {err}"
        );
    }

    /// §4 test 2: a moved endpoint on either node fails the WHOLE report —
    /// even when every other check would have passed.
    #[test]
    fn wire_replay_report_with_moved_endpoint_fails() {
        let mut report = good_report();
        report["nodes"][1]["endpoint_pair_after"] =
            serde_json::json!(endpoint_pair("10.0.0.1", "10.0.0.9"));
        let err = evaluate_wire_replay_report(&report.to_string(), &expected_correlation())
            .expect_err("a moved endpoint must fail the report");
        assert!(
            err.contains("session_endpoint_immovable FAILED") && err.contains("moved"),
            "should name the moved endpoint, got: {err}"
        );

        // The immovable OTHER node does not rescue the report: the failure
        // names the moved node specifically.
        assert!(
            err.contains("exit-1"),
            "should name the node whose endpoint moved, got: {err}"
        );
    }

    /// §4 test 3: a fixture whose nonce was never consumed by the receiver
    /// is refused — the replay precondition was never established.
    #[test]
    fn fixture_with_unconsumed_nonce_is_refused() {
        let mut fixture = good_fixture();
        fixture.nonce_consumed_by_receiver = false;
        let err = validate_replay_fixture(&fixture)
            .expect_err("an unconsumed nonce must refuse the fixture");
        assert_eq!(err, FixtureRefusal::NonceNotConsumedByReceiver);
        assert_eq!(err.reason(), "nonce not consumed by receiver");
    }

    /// §4 test 4: a fixture with an invalid signature is refused — a bad
    /// signature is an InvalidFormat rejection in the daemon, never evidence
    /// of replay rejection (§2.2).
    #[test]
    fn fixture_with_invalid_signature_is_refused() {
        let mut fixture = good_fixture();
        fixture.signature_valid = false;
        let err = validate_replay_fixture(&fixture)
            .expect_err("an invalid signature must refuse the fixture");
        assert_eq!(err, FixtureRefusal::SignatureInvalid);
    }

    /// §4 test 5: a missing/empty report string is a FAIL, never a skip.
    #[test]
    fn missing_report_is_fail_not_skip() {
        for absent in ["", "   \n\t "] {
            let err = evaluate_wire_replay_report(absent, &expected_correlation())
                .expect_err("a missing report must fail, never skip");
            assert!(
                err.contains("missing or empty") && err.contains("never a skip"),
                "should classify the absent report as fail-not-skip, got: {err}"
            );
        }
    }

    /// §4 test 6 (A5): a fixture whose envelope was already expired at
    /// capture on the DAEMON clock is refused.
    #[test]
    fn staleness_rejection_with_expired_at_capture_fixture_is_refused() {
        let mut fixture = good_fixture();
        fixture.envelope_expires_at_unix = 4000;
        fixture.daemon_now_unix_at_capture = 4000;
        let err = validate_replay_fixture(&fixture)
            .expect_err("an envelope expired at capture must refuse the fixture");
        assert_eq!(err, FixtureRefusal::ExpiredAtCapture);

        let mut strictly_expired = good_fixture();
        strictly_expired.envelope_expires_at_unix = 3999;
        strictly_expired.daemon_now_unix_at_capture = 4000;
        assert_eq!(
            validate_replay_fixture(&strictly_expired).expect_err("strictly-expired must refuse"),
            FixtureRefusal::ExpiredAtCapture,
        );
    }

    /// §4 test 7: a dry-run marker cannot pass a live replay-rejection check.
    #[test]
    fn dry_run_marker_cannot_pass() {
        let mut report = good_report();
        report["dry_run"] = serde_json::json!(true);
        let err = evaluate_wire_replay_report(&report.to_string(), &expected_correlation())
            .expect_err("a dry-run report must never pass");
        assert!(
            err.contains("dry_run marker"),
            "should name the dry-run marker, got: {err}"
        );
    }

    /// §4 test 8 (A7): a validator failure mid-soak or an incomplete soak
    /// fails the report even when the recorded checks would pass.
    #[test]
    fn validator_failure_mid_soak_or_incomplete_soak_is_fail() {
        let mut report = good_report();
        report["soak_complete"] = serde_json::json!(false);
        let err = evaluate_wire_replay_report(&report.to_string(), &expected_correlation())
            .expect_err("an incomplete soak must fail");
        assert!(
            err.contains("soak incomplete") && err.contains("A7"),
            "should name the incomplete soak, got: {err}"
        );
    }

    // ── Positive and attribution tests ───────────────────────────────────────

    /// The positive case: an attributable watermark rejection with an
    /// immovable, live session earns all four checks.
    #[test]
    fn accepts_attributable_watermark_rejection_with_immovable_session() {
        let summary = evaluate_good().expect("the all-good report must pass");
        assert!(summary.contains("wire_replay_rejected"), "{summary}");
        assert!(
            summary.contains("session_endpoint_immovable (2/2"),
            "{summary}"
        );
        assert!(summary.contains("hint_generation_stable (7)"), "{summary}");
        assert!(summary.contains("session_survives_replay"), "{summary}");

        // `replay_detected` and `generation` reason classes earn it too.
        for reason in ["replay_detected", "generation"] {
            let mut report = good_report();
            report["rejection_record"]["reason_class"] = serde_json::json!(reason);
            assert!(
                evaluate_wire_replay_report(&report.to_string(), &expected_correlation()).is_ok(),
                "reason class '{reason}' must be attributable"
            );
        }
    }

    /// A lost fetch race is UNATTRIBUTABLE: the injected bundle may have been
    /// overwritten by `state_fetcher.fetch_traversal` before the daemon ever
    /// loaded it (A4c), so any observed outcome proves nothing.
    #[test]
    fn lost_fetch_race_is_unattributable_not_pass() {
        let mut report = good_report();
        report["fetch_race"] = serde_json::json!("lost");
        let err = evaluate_wire_replay_report(&report.to_string(), &expected_correlation())
            .expect_err("a lost fetch race must not pass");
        assert!(
            err.contains("UNATTRIBUTABLE") && err.contains("fetch race"),
            "should classify the lost race as unattributable, got: {err}"
        );
    }

    /// An unobserved refresh trigger is UNATTRIBUTABLE: the injected bundle
    /// was never loaded, so a silent drop cannot be distinguished from a
    /// rejection (§2.3).
    #[test]
    fn unobserved_refresh_trigger_is_unattributable_not_pass() {
        let mut report = good_report();
        report["refresh_trigger"]["observed"] = serde_json::json!(false);
        let err = evaluate_wire_replay_report(&report.to_string(), &expected_correlation())
            .expect_err("an unobserved refresh must not pass");
        assert!(
            err.contains("UNATTRIBUTABLE") && err.contains("never observed"),
            "should classify the unobserved refresh as unattributable, got: {err}"
        );

        // Observed but WITHOUT a call-site label is equally unattributable.
        let mut unlabeled = good_report();
        unlabeled["refresh_trigger"]["call_site"] = serde_json::json!(null);
        let err = evaluate_wire_replay_report(&unlabeled.to_string(), &expected_correlation())
            .expect_err("an unlabeled refresh must not pass");
        assert!(
            err.contains("without a call-site label"),
            "should name the missing call-site label, got: {err}"
        );

        let mut blank = good_report();
        blank["refresh_trigger"]["call_site"] = serde_json::json!("   ");
        assert!(
            evaluate_wire_replay_report(&blank.to_string(), &expected_correlation())
                .expect_err("a blank call-site label must not pass")
                .contains("without a call-site label"),
        );
    }

    /// A rejection record that does not correlate to the injected fixture's
    /// nonce AND digest is UNATTRIBUTABLE (A4b).
    #[test]
    fn correlation_mismatch_is_not_pass() {
        let mut wrong_nonce = good_report();
        wrong_nonce["rejection_record"]["nonce"] = serde_json::json!("nonce-other");
        let err = evaluate_wire_replay_report(&wrong_nonce.to_string(), &expected_correlation())
            .expect_err("a nonce mismatch must not pass");
        assert!(
            err.contains("does not correlate"),
            "should name the correlation mismatch, got: {err}"
        );

        let mut wrong_digest = good_report();
        wrong_digest["rejection_record"]["payload_digest"] = serde_json::json!("digest-other");
        assert!(
            evaluate_wire_replay_report(&wrong_digest.to_string(), &expected_correlation())
                .expect_err("a digest mismatch must not pass")
                .contains("does not correlate"),
        );
    }

    /// `invalid_format` NEVER passes: it means the fixture was mangled, not
    /// replay-rejected (§2.2).
    #[test]
    fn invalid_format_rejection_is_not_pass() {
        let mut report = good_report();
        report["rejection_record"]["reason_class"] = serde_json::json!("invalid_format");
        let err = evaluate_wire_replay_report(&report.to_string(), &expected_correlation())
            .expect_err("an invalid_format rejection must never pass");
        assert!(
            err.contains("invalid_format") && err.contains("mangled"),
            "should name invalid_format as mangled-fixture, got: {err}"
        );

        // An unknown reason class is equally unattributable.
        let mut unknown = good_report();
        unknown["rejection_record"]["reason_class"] = serde_json::json!("something_else");
        assert!(
            evaluate_wire_replay_report(&unknown.to_string(), &expected_correlation())
                .expect_err("an unknown reason class must not pass")
                .contains("unknown rejection reason_class"),
        );
    }

    /// A `stale` rejection only earns the check when the envelope was within
    /// TTL at capture on the DAEMON's clock (A5); without that evidence the
    /// daemon merely rejected an already-dead envelope.
    #[test]
    fn stale_reason_without_daemon_clock_ttl_evidence_is_not_pass() {
        let mut report = good_report();
        report["rejection_record"]["reason_class"] = serde_json::json!("stale");
        // Within TTL at capture: earned.
        assert!(
            evaluate_wire_replay_report(&report.to_string(), &expected_correlation()).is_ok(),
            "a stale rejection with in-TTL evidence must pass"
        );

        // Already expired at capture: not earned.
        report["envelope_expires_at_unix"] = serde_json::json!(4000);
        report["daemon_now_unix_at_capture"] = serde_json::json!(4000);
        let err = evaluate_wire_replay_report(&report.to_string(), &expected_correlation())
            .expect_err("a stale rejection on an expired envelope must not pass");
        assert!(
            err.contains("daemon-clock TTL evidence"),
            "should name the missing TTL evidence, got: {err}"
        );
    }

    // ── A3 fixture guards ────────────────────────────────────────────────────

    /// A fixture whose envelope watermark is not STRICTLY older than the
    /// live watermark is refused: equal-with-same-digest is the current
    /// bundle (not a replay sample) and a newer envelope is future-dated.
    #[test]
    fn fixture_not_strictly_older_than_live_watermark_is_refused() {
        let mut equal_same_digest = good_fixture();
        equal_same_digest.envelope_watermark.generated_at_unix = 2000;
        equal_same_digest.envelope_watermark.payload_digest =
            equal_same_digest.live_watermark.payload_digest.clone();
        assert_eq!(
            validate_replay_fixture(&equal_same_digest)
                .expect_err("equal-with-same-digest is the current bundle, not a replay")
                .reason(),
            "envelope watermark not strictly older than live watermark",
        );

        let mut equal_other_digest = good_fixture();
        equal_other_digest.envelope_watermark.generated_at_unix = 2000;
        assert_eq!(
            validate_replay_fixture(&equal_other_digest)
                .expect_err("equal-with-different-digest is a divergence sample")
                .reason(),
            "envelope watermark not strictly older than live watermark",
        );

        let mut newer = good_fixture();
        newer.envelope_watermark.generated_at_unix = 3000;
        assert_eq!(
            validate_replay_fixture(&newer)
                .expect_err("a newer envelope is future-dated, not an old bundle")
                .reason(),
            "envelope watermark not strictly older than live watermark",
        );
    }

    /// A fixture that violates the single-snapshot contract is refused: the
    /// daemon would emit `InvalidFormat` (daemon.rs:15455-15463), which can
    /// never score as a replay pass (§2.2).
    #[test]
    fn fixture_not_single_snapshot_is_refused() {
        let mut fixture = good_fixture();
        fixture.single_snapshot = false;
        assert_eq!(
            validate_replay_fixture(&fixture)
                .expect_err("a torn snapshot must refuse the fixture")
                .reason(),
            "single-snapshot contract not intact",
        );
    }

    /// A2 vantage: an injector that ran on the coordinator fails the report
    /// outright, whatever the checks say.
    #[test]
    fn injector_on_coordinator_fails() {
        let mut report = good_report();
        report["injector_ran_on_coordinator"] = serde_json::json!(true);
        let err = evaluate_wire_replay_report(&report.to_string(), &expected_correlation())
            .expect_err("an on-coordinator injector must fail the vantage assertion");
        assert!(
            err.contains("vantage violated") && err.contains("coordinator"),
            "should name the vantage violation, got: {err}"
        );

        // And the mirror-image vantage assertion: control-plane delivery.
        let mut shortcut = good_report();
        shortcut["delivered_via_real_bundle_path"] = serde_json::json!(false);
        let err = evaluate_wire_replay_report(&shortcut.to_string(), &expected_correlation())
            .expect_err("a non-bundle-path delivery must fail the vantage assertion");
        assert!(
            err.contains("real bundle path"),
            "should name the bundle-path vantage violation, got: {err}"
        );
    }

    /// The watermark ordering mirrors the daemon's anti-rollback semantics
    /// (daemon.rs:15486-15501): strictly-older and
    /// equal-with-different-digest are rejected as replays;
    /// equal-with-same-digest and newer are not.
    #[test]
    fn watermark_ordering_mirrors_daemon_anti_rollback() {
        let live = Watermark {
            generated_at_unix: 2000,
            nonce: "nonce-live".to_owned(),
            payload_digest: "digest-live".to_owned(),
        };

        let strictly_older = Watermark {
            generated_at_unix: 1999,
            nonce: "nonce-old".to_owned(),
            payload_digest: "digest-old".to_owned(),
        };
        assert!(
            strictly_older.is_replay_of(&live),
            "Less-than-persisted must be rejected as a replay"
        );

        // `Equal` in the daemon's ordering means the same generation AND the
        // same nonce (daemon.rs:16523-16531); only then does the digest decide.
        let equal_other_digest = Watermark {
            generated_at_unix: 2000,
            nonce: "nonce-live".to_owned(),
            payload_digest: "digest-other".to_owned(),
        };
        assert!(
            equal_other_digest.is_replay_of(&live),
            "Equal-with-different-digest must be rejected as a replay"
        );

        let equal_same_digest = Watermark {
            generated_at_unix: 2000,
            nonce: "nonce-live".to_owned(),
            payload_digest: "digest-live".to_owned(),
        };
        assert!(
            !equal_same_digest.is_replay_of(&live),
            "Equal-with-same-digest is the current bundle, not a replay"
        );

        // Same generation, different nonce: the nonce tiebreak decides, exactly
        // as the daemon orders it — a lesser nonce is a rollback, a greater one
        // is not a replay at this layer (even with the same digest).
        let same_generation_lesser_nonce = Watermark {
            generated_at_unix: 2000,
            nonce: "nonce-a".to_owned(),
            payload_digest: "digest-live".to_owned(),
        };
        assert_eq!(
            same_generation_lesser_nonce.ordering_against(&live),
            Ordering::Less
        );
        assert!(
            same_generation_lesser_nonce.is_replay_of(&live),
            "same generation with a lesser nonce orders Less and is rejected"
        );
        let same_generation_greater_nonce = Watermark {
            generated_at_unix: 2000,
            nonce: "nonce-z".to_owned(),
            payload_digest: "digest-other".to_owned(),
        };
        assert_eq!(
            same_generation_greater_nonce.ordering_against(&live),
            Ordering::Greater
        );
        assert!(
            !same_generation_greater_nonce.is_replay_of(&live),
            "same generation with a greater nonce orders Greater and is not a replay"
        );

        let newer = Watermark {
            generated_at_unix: 2001,
            nonce: "nonce-new".to_owned(),
            payload_digest: "digest-old".to_owned(),
        };
        assert!(
            !newer.is_replay_of(&live),
            "Newer-than-persisted is not a replay at this layer"
        );
    }

    /// Malformed JSON and schema-version drift fail closed with named
    /// reasons (§3.3); a schema-less report is not a pass either.
    #[test]
    fn malformed_json_and_unknown_schema_fail_closed() {
        let err = evaluate_wire_replay_report("{not json", &expected_correlation())
            .expect_err("malformed JSON must be rejected");
        assert!(
            err.contains("parse wire-replay report JSON failed"),
            "should name the parse failure, got: {err}"
        );

        let mut unsupported = good_report();
        unsupported["schema_version"] = serde_json::json!(2);
        let err = evaluate_wire_replay_report(&unsupported.to_string(), &expected_correlation())
            .expect_err("an unsupported schema version must be rejected");
        assert!(
            err.contains("unsupported schema_version=2"),
            "should reject the schema drift, got: {err}"
        );

        let mut absent = good_report();
        absent
            .as_object_mut()
            .expect("object")
            .remove("schema_version");
        let err = evaluate_wire_replay_report(&absent.to_string(), &expected_correlation())
            .expect_err("a schema-less report must be rejected");
        assert!(
            err.contains("missing schema_version"),
            "should name the missing schema_version, got: {err}"
        );
    }
}
