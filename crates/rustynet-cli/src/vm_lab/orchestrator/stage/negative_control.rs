#![allow(dead_code)]
//! # T5 negative-control suite — the adjudication half of the G1 trust bar
//!
//! `NodeEngineAcceptanceSpec_2026-07-23.md` §3-T5 / §5. A2 (the independent
//! evidence verifier) proves a GREEN is *trustworthy*; T5 proves the engine
//! can be **made to fail correctly** — for each injected fault, the specific
//! targeted stage must terminate a NON-pass for the *named* reason
//! (RED-for-the-right-reason). Without T5 an engine that rubber-stamps every
//! stage green would clear the bar.
//!
//! ## The inversion (the load-bearing design constraint)
//!
//! [`StageOutcome`] is binary — there is no "expect-RED" outcome, and
//! `overall_result` is fail-dominated (any hard [`StageOutcome::Failed`] fails
//! the run). So a negative control cannot simply plant a fault and let the
//! target stage fail in the normal pipeline. Instead each control **plants its
//! fault, exercises the targeted operation, and ADJUDICATES that the target's
//! outcome is a non-pass for the specific expected reason**. The control itself
//! returns [`StageOutcome::Passed`] iff the target failed correctly, and
//! [`StageOutcome::Failed`] if the target unexpectedly passed (a fail-open) OR
//! failed for the wrong reason.
//!
//! This binds to the A2 verifier's exit-code semantics
//! (`crates/rustynet-cli/src/bin/live_lab_evidence_verifier.rs`): a
//! correctly-adjudicated RED is a *valid non-pass* (verifier exit 2), distinct
//! from broken evidence (exit 1). A control that passes is asserting the
//! engine produced a valid-non-pass on its targeted stage.
//!
//! ## GUARD — never loosen what counts as a rejection
//!
//! A control asserts REAL fail-closed behavior against the *named* expected
//! rejection. It must never accept "any error", nor accept a weak/wrong
//! rejection to make itself pass — a lenient control is itself a rubber-stamp
//! and is worse than no control. Every adjudicator here distinguishes
//! `RejectedAsExpected` from `RejectedWrongReason` and from
//! `AcceptedButMustReject`, and only the first is a control pass.
//!
//! ## What runs locally now vs deferred-to-live-verify (increment A3a)
//!
//! - **(b) signed-bundle rejection** and **(d) wrong-node substitution** drive
//!   the real `verify_signed_assignment_state_artifact` verifier against forged
//!   assignment bundles minted in-process — fully local, no guest, so their
//!   [`OrchestrationStage::execute`] adjudicates for real.
//! - **(a) planted residue** and **(c) daemon-killed-mid-stage** need a live
//!   guest to plant the fault; their pure adjudication logic is built and
//!   unit-tested here, but `execute` returns [`StageOutcome::Skipped`] with a
//!   deferred-to-live-verify reason (the live fault-injection lands in a later
//!   live-verify phase, like `network_flap`).
use crate::vm_lab::orchestrator::adapter::linux_traffic::parse_node_clean_probe;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};
use std::path::{Path, PathBuf};

// ── The four control StageIds ────────────────────────────────────────────────

/// (b) Signed-bundle rejection — drives `verify_signed_assignment_state_artifact`
/// against a forged-bundle corpus; passes iff every forgery is rejected
/// fail-closed matching its NAMED rejection AND a genuine bundle is accepted.
/// Runs locally.
pub struct NegativeControlSignedBundleRejectionStage;

/// (a) Planted residue → Cleanup FAIL — adjudication over the pure
/// `parse_node_clean_probe`: a dirty probe must drive the clean-assert to
/// `Err`. Live planting on a guest is deferred to live-verify.
pub struct NegativeControlPlantedResidueStage;

/// (d) Wrong-node substitution → validator FAIL — drives
/// `verify_signed_assignment_state_artifact` with a mismatched
/// `expected_node_id`; passes iff the mismatch is rejected AND the matching id
/// is accepted. Runs locally at the verify-path level (see the
/// orchestrator-threading note on [`NegativeControlWrongNodeSubstitutionStage`]).
pub struct NegativeControlWrongNodeSubstitutionStage;

/// (c) Daemon-killed-mid-stage → stage not pass — adjudication asserts the
/// targeted stage's recorded outcome is NOT a pass under a mid-stage kill. The
/// live kill reuses the existing `live_chaos_daemon_fault_test` kill primitive
/// (`render_remote_kill_script`) and is deferred to live-verify.
pub struct NegativeControlDaemonKillMidStageStage;

// ── Suite dependency shape ───────────────────────────────────────────────────
//
// The controls are self-contained (offline crypto for b/d; deferred for a/c),
// so they carry no stage dependencies — the opt-in suite can run in a filtered
// plan without a full live topology having been brought up first.
const NO_DEPS: &[StageId] = &[];
const NO_ROLES: &[NodeRole] = &[];

impl OrchestrationStage for NegativeControlSignedBundleRejectionStage {
    fn id(&self) -> StageId {
        StageId::NegativeControlSignedBundleRejection
    }
    fn name(&self) -> &str {
        "negative_control_signed_bundle_rejection"
    }
    fn dependencies(&self) -> &[StageId] {
        NO_DEPS
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        NO_ROLES
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }
    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let dir = control_workdir(ctx, self.name());
        signed_bundle::run_signed_bundle_control(&dir)
    }
}

impl OrchestrationStage for NegativeControlWrongNodeSubstitutionStage {
    fn id(&self) -> StageId {
        StageId::NegativeControlWrongNodeSubstitution
    }
    fn name(&self) -> &str {
        "negative_control_wrong_node_substitution"
    }
    fn dependencies(&self) -> &[StageId] {
        NO_DEPS
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        NO_ROLES
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }
    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let dir = control_workdir(ctx, self.name());
        signed_bundle::run_wrong_node_control(&dir)
    }
}

impl OrchestrationStage for NegativeControlPlantedResidueStage {
    fn id(&self) -> StageId {
        StageId::NegativeControlPlantedResidue
    }
    fn name(&self) -> &str {
        "negative_control_planted_residue"
    }
    fn dependencies(&self) -> &[StageId] {
        NO_DEPS
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        NO_ROLES
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }
    fn execute(&self, _ctx: &mut OrchestrationContext) -> StageOutcome {
        // The pure adjudication ([`adjudicate_planted_residue`]) is built and
        // unit-tested; planting real `rustynet*` residue on a live guest and
        // driving `assert_node_clean` is deferred to the live-verify phase.
        StageOutcome::Skipped
    }
}

impl OrchestrationStage for NegativeControlDaemonKillMidStageStage {
    fn id(&self) -> StageId {
        StageId::NegativeControlDaemonKillMidStage
    }
    fn name(&self) -> &str {
        "negative_control_daemon_kill_mid_stage"
    }
    fn dependencies(&self) -> &[StageId] {
        NO_DEPS
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        NO_ROLES
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }
    fn execute(&self, _ctx: &mut OrchestrationContext) -> StageOutcome {
        // The pure adjudication ([`adjudicate_daemon_kill_outcome`]) is built
        // and unit-tested; the live mid-stage `systemctl kill -s KILL` reuses
        // the existing `live_chaos_daemon_fault_test` kill primitive and is
        // deferred to the live-verify phase.
        StageOutcome::Skipped
    }
}

/// Per-control scratch directory under the run's report dir.
fn control_workdir(ctx: &OrchestrationContext, stage_name: &str) -> PathBuf {
    ctx.report_dir.join("negative_control").join(stage_name)
}

// ── (a) planted-residue adjudication (pure) ──────────────────────────────────

/// Outcome of adjudicating control (a) against a clean-probe line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ResidueControlOutcome {
    /// The planted residue was detected (the clean-assert parser returned
    /// `Err`). The control PASSES: the residue stage would correctly FAIL.
    ResidueDetected(String),
    /// The parser passed a node that carries planted residue — a fail-OPEN.
    /// The control FAILS: this is exactly the defect the residue control
    /// exists to catch (the historical Pair-1 `rustynet_boot` false-clean).
    FailOpenResidueMissed,
}

impl ResidueControlOutcome {
    pub(crate) fn is_control_pass(&self) -> bool {
        matches!(self, ResidueControlOutcome::ResidueDetected(_))
    }
}

/// Adjudicate control (a): a DIRTY clean-probe output (a leftover `rustynet*`
/// nft table, a daemon still up, or a leftover `rustynet*` interface) MUST
/// drive the pure [`parse_node_clean_probe`] to `Err`. The control passes iff
/// the residue is detected; a probe that reports a residue-carrying node clean
/// is a fail-open and fails the control.
pub(crate) fn adjudicate_planted_residue(dirty_probe_output: &str) -> ResidueControlOutcome {
    match parse_node_clean_probe(dirty_probe_output) {
        Err(err) => ResidueControlOutcome::ResidueDetected(err.to_string()),
        Ok(()) => ResidueControlOutcome::FailOpenResidueMissed,
    }
}

// ── (c) daemon-kill adjudication (pure) ──────────────────────────────────────

/// Outcome of adjudicating control (c) against a stage's recorded outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KillControlOutcome {
    /// The targeted stage recorded a non-pass terminal state under the
    /// mid-stage kill. The control PASSES.
    StageDidNotPass,
    /// The targeted stage reported `Passed` despite the daemon being killed
    /// mid-stage — a false-green. The control FAILS.
    FalseGreenUnderKill,
}

impl KillControlOutcome {
    pub(crate) fn is_control_pass(&self) -> bool {
        matches!(self, KillControlOutcome::StageDidNotPass)
    }
}

/// Adjudicate control (c): under a mid-stage daemon kill the targeted stage's
/// recorded outcome MUST NOT be a pass. Any non-pass terminal state
/// (`Failed`/`Skipped`/`NotRun`/`Reused`) satisfies the control; a `Passed`
/// under the kill is a false-green and fails the control.
///
/// Note the strictness: a `Reused` outcome is NOT a pass and so satisfies the
/// control, but it must never be *read as* a fresh pass — matching the §4.2
/// terminal-state taxonomy the A2 verifier enforces.
pub(crate) fn adjudicate_daemon_kill_outcome(recorded: &StageOutcome) -> KillControlOutcome {
    match recorded {
        StageOutcome::Passed => KillControlOutcome::FalseGreenUnderKill,
        StageOutcome::Failed(_)
        | StageOutcome::Skipped
        | StageOutcome::NotRun
        | StageOutcome::Reused { .. } => KillControlOutcome::StageDidNotPass,
    }
}

// ── (b) + (d) signed-bundle forgery corpus + adjudication ────────────────────

pub(crate) mod signed_bundle {
    //! Drives the REAL `verify_signed_assignment_state_artifact`
    //! (`crates/rustynetd/src/daemon.rs`) against assignment-bundle forgeries.
    //!
    //! The forgery taxonomy mirrors the `live_signed_state_chaos` corpus
    //! (`bin/live_signed_state_chaos/mod.rs`, `ALL_SCENARIOS`): each scenario
    //! carries a corpus id + the corpus `expected_rejection` label. The corpus
    //! fixture BYTES are format-agnostic JSON blobs (a truncated `{`, a
    //! future-dated JSON object, …) — fed raw to the assignment verifier they
    //! would ALL collapse to a single `invalid format` error, which cannot
    //! distinguish future-dated from forged-signature from replay and would
    //! make the control a rubber-stamp (the guard forbids "accepts any
    //! error"). So each scenario is realised as a *properly assignment-shaped*
    //! forgery that reaches the verifier's SPECIFIC rejection path, and the
    //! adjudicator asserts the actual error names that specific reason.
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rustynetd::daemon::verify_signed_assignment_state_artifact;

    /// hex([9u8; 32]) — the daemon's known-good genuine-bundle peer key.
    const PEER_PUBLIC_KEY_HEX: &str =
        "0909090909090909090909090909090909090909090909090909090909090909";
    /// Freshness envelope the genuine bundle sits well inside.
    const MAX_AGE_SECS: u64 = 300;
    const MAX_CLOCK_SKEW_SECS: u64 = 60;
    /// Signing seed for the authorised signer (matches the daemon's test
    /// helper `write_auto_tunnel_file`, so the genuine bundle loads).
    const AUTHORISED_SIGNER_SEED: [u8; 32] = [19u8; 32];
    /// A DIFFERENT, unauthorised signer used for the forged-signature case.
    const UNAUTHORISED_SIGNER_SEED: [u8; 32] = [7u8; 32];
    /// The node the genuine/forged bundles are minted for.
    const BUNDLE_NODE_ID: &str = "nc-node-local";

    fn hex_encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    fn unix_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// The daemon's known-good signed-assignment payload (the exact shape
    /// `write_auto_tunnel_file` mints, which loads + passes route-intent), with
    /// the node id / freshness parametrised.
    fn genuine_payload(node_id: &str, generated_at: u64, expires_at: u64, nonce: u64) -> String {
        format!(
            "version=1\n\
             node_id={node_id}\n\
             node_capabilities=anchor,client\n\
             mesh_cidr=100.64.0.0/10\n\
             assigned_cidr=100.64.0.1/32\n\
             exit_node_id=node-exit\n\
             exit_node_capabilities=exit_server\n\
             traffic_route_policy=mesh_or_relay_or_exit_node\n\
             generated_at_unix={generated_at}\n\
             expires_at_unix={expires_at}\n\
             nonce={nonce}\n\
             peer_count=1\n\
             peer.0.node_id=node-exit\n\
             peer.0.capabilities=exit_server\n\
             peer.0.endpoint=203.0.113.20:51820\n\
             peer.0.public_key_hex={PEER_PUBLIC_KEY_HEX}\n\
             peer.0.allowed_ips=0.0.0.0/0,100.64.0.2/32\n\
             route_count=2\n\
             route.0.destination_cidr=100.64.0.2/32\n\
             route.0.via_node=node-exit\n\
             route.0.kind=mesh\n\
             route.1.destination_cidr=0.0.0.0/0\n\
             route.1.via_node=node-exit\n\
             route.1.kind=exit_default\n"
        )
    }

    /// Sign `payload` with `seed` and append the `signature=` line.
    fn sign_bundle(payload: &str, seed: &[u8; 32]) -> String {
        let signing_key = SigningKey::from_bytes(seed);
        let signature = signing_key.sign(payload.as_bytes());
        format!("{payload}signature={}\n", hex_encode(&signature.to_bytes()))
    }

    /// The verifier-key file content for the AUTHORISED signer.
    fn authorised_verifier_key() -> String {
        let signing_key = SigningKey::from_bytes(&AUTHORISED_SIGNER_SEED);
        format!("{}\n", hex_encode(signing_key.verifying_key().as_bytes()))
    }

    /// A version-2 assignment watermark file whose `generated_at_unix` sits at
    /// `watermark_generated_at` (the payload digest is a benign constant — the
    /// verifier only consults it on the equal-watermark branch, which none of
    /// these scenarios exercises).
    fn watermark_file(watermark_generated_at: u64) -> String {
        format!(
            "version=2\n\
             generated_at_unix={watermark_generated_at}\n\
             nonce=1\n\
             payload_digest_sha256={}\n",
            "0".repeat(64)
        )
    }

    /// One forged assignment bundle bound to a specific named rejection.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct BundleScenario {
        /// The `live_signed_state_chaos` corpus scenario id this mirrors.
        pub(crate) corpus_id: &'static str,
        /// The corpus `expected_rejection` label (the NAMED rejection).
        pub(crate) expected_rejection: &'static str,
        /// How the assignment bundle is corrupted.
        pub(crate) kind: ForgeryKind,
        /// The substring the verifier's error MUST contain for the rejection
        /// to count as the *named* rejection (the guard: a weak/wrong reason
        /// does not satisfy the control).
        pub(crate) required_error_substr: &'static str,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum ForgeryKind {
        /// A single `{` byte — a truncated bundle.
        TruncatedOneByte,
        /// The first half of the genuine payload, no signature.
        TruncatedHalfLength,
        /// A well-formed, correctly-signed bundle dated beyond the clock skew.
        FutureDated,
        /// A well-formed bundle signed by an unauthorised key.
        ForgedSignature,
        /// A genuine, current bundle presented against a strictly-newer
        /// persisted watermark (an anti-replay regression).
        Replay,
    }

    /// The assignment-scoped forgery corpus, keyed off `ALL_SCENARIOS`.
    ///
    /// The corpus's `quorum_starved_update` scenario is deliberately absent:
    /// quorum is a MEMBERSHIP-layer concept, and `verify_signed_assignment_state_artifact`
    /// (an assignment-bundle verifier) has no quorum code path. Forcing a
    /// synthetic "quorum" rejection onto the assignment verifier would be a
    /// fabricated control; that fault class is adjudicated on the membership
    /// path (the offline `chaos_signed_state_adversarial` corpus + the
    /// `validate_linux_membership_signature_forgery` audit), not here.
    pub(crate) const SCENARIOS: &[BundleScenario] = &[
        BundleScenario {
            corpus_id: "truncated_one_byte",
            expected_rejection: "malformed_truncated_one_byte",
            kind: ForgeryKind::TruncatedOneByte,
            required_error_substr: "invalid format",
        },
        BundleScenario {
            corpus_id: "truncated_half_length",
            expected_rejection: "malformed_truncated_half_length",
            kind: ForgeryKind::TruncatedHalfLength,
            required_error_substr: "invalid format",
        },
        BundleScenario {
            corpus_id: "future_dated_assignment",
            expected_rejection: "future_dated_signed_state",
            kind: ForgeryKind::FutureDated,
            required_error_substr: "future dated",
        },
        BundleScenario {
            corpus_id: "forged_signature_attempt",
            expected_rejection: "unauthorised_signature",
            kind: ForgeryKind::ForgedSignature,
            required_error_substr: "signature verification failed",
        },
        BundleScenario {
            corpus_id: "replay_watermarked_membership",
            expected_rejection: "replay_watermark_regression",
            kind: ForgeryKind::Replay,
            required_error_substr: "replay detected",
        },
    ];

    /// Per-scenario classification (the inversion: only `RejectedAsExpected`
    /// is a control pass).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) enum RejectionCheck {
        /// Rejected fail-closed with an error naming the expected reason.
        RejectedAsExpected,
        /// ACCEPTED — a fail-open. The control FAILS.
        AcceptedButMustReject,
        /// Rejected, but not for the named reason (the guard: a weak/wrong
        /// rejection is not a control pass).
        RejectedWrongReason { actual: String },
    }

    impl RejectionCheck {
        pub(crate) fn is_control_pass(&self) -> bool {
            matches!(self, RejectionCheck::RejectedAsExpected)
        }
    }

    /// Positive-control classification for the genuine bundle.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) enum AcceptanceCheck {
        /// Accepted, as a genuine bundle must be.
        AcceptedAsExpected,
        /// Rejected — the verifier is over-strict / the positive control is
        /// broken; the control FAILS (a control that rejects everything,
        /// including valid input, is not proving fail-CLOSED, it is broken).
        RejectedButMustAccept { actual: String },
    }

    impl AcceptanceCheck {
        pub(crate) fn is_control_pass(&self) -> bool {
            matches!(self, AcceptanceCheck::AcceptedAsExpected)
        }
    }

    /// Write the three artifacts for a scenario and return the bundle,
    /// verifier-key and watermark paths.
    fn write_scenario(dir: &Path, kind: ForgeryKind) -> Result<Fixture, String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        let now = unix_now();
        let (bundle_body, watermark_generated_at) = match kind {
            ForgeryKind::TruncatedOneByte => ("{".to_owned(), 1),
            ForgeryKind::TruncatedHalfLength => {
                let payload = genuine_payload(BUNDLE_NODE_ID, now, now + 300, 7);
                let half = payload.len() / 2;
                (payload[..half].to_owned(), 1)
            }
            ForgeryKind::FutureDated => {
                let generated = now + 100_000;
                let payload = genuine_payload(BUNDLE_NODE_ID, generated, generated + 300, 7);
                (sign_bundle(&payload, &AUTHORISED_SIGNER_SEED), 1)
            }
            ForgeryKind::ForgedSignature => {
                let payload = genuine_payload(BUNDLE_NODE_ID, now, now + 300, 7);
                (sign_bundle(&payload, &UNAUTHORISED_SIGNER_SEED), 1)
            }
            ForgeryKind::Replay => {
                let payload = genuine_payload(BUNDLE_NODE_ID, now, now + 300, 7);
                // Persisted watermark strictly newer than this bundle ⇒ the
                // incoming bundle regresses the anti-replay watermark.
                (sign_bundle(&payload, &AUTHORISED_SIGNER_SEED), now + 100)
            }
        };
        write_fixture(dir, &bundle_body, watermark_generated_at)
    }

    /// A genuine, current, authorised bundle with a benign (older) watermark.
    fn write_genuine(dir: &Path, node_id: &str) -> Result<Fixture, String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        let now = unix_now();
        let payload = genuine_payload(node_id, now, now + 300, 7);
        let body = sign_bundle(&payload, &AUTHORISED_SIGNER_SEED);
        write_fixture(dir, &body, 1)
    }

    struct Fixture {
        bundle: PathBuf,
        verifier_key: PathBuf,
        watermark: PathBuf,
    }

    fn write_fixture(
        dir: &Path,
        bundle_body: &str,
        watermark_generated_at: u64,
    ) -> Result<Fixture, String> {
        let bundle = dir.join("assignment.bundle");
        let verifier_key = dir.join("assignment.verifier.pub");
        let watermark = dir.join("assignment.watermark");
        std::fs::write(&bundle, bundle_body)
            .map_err(|e| format!("write {}: {e}", bundle.display()))?;
        std::fs::write(&verifier_key, authorised_verifier_key())
            .map_err(|e| format!("write {}: {e}", verifier_key.display()))?;
        std::fs::write(&watermark, watermark_file(watermark_generated_at))
            .map_err(|e| format!("write {}: {e}", watermark.display()))?;
        Ok(Fixture {
            bundle,
            verifier_key,
            watermark,
        })
    }

    /// Run the assignment verifier against a fixture with the given
    /// `expected_node_id`.
    fn verify(fixture: &Fixture, expected_node_id: Option<&str>) -> Result<(), String> {
        verify_signed_assignment_state_artifact(
            &fixture.bundle,
            &fixture.verifier_key,
            &fixture.watermark,
            MAX_AGE_SECS,
            MAX_CLOCK_SKEW_SECS,
            expected_node_id,
        )
        .map(|_report| ())
    }

    /// Adjudicate one forgery scenario.
    pub(crate) fn adjudicate_scenario(dir: &Path, scenario: &BundleScenario) -> RejectionCheck {
        let fixture = match write_scenario(dir, scenario.kind) {
            Ok(fixture) => fixture,
            // A fixture we could not even stage is a wrong-reason rejection, not
            // a pass — never silently swallow it into a control pass.
            Err(err) => {
                return RejectionCheck::RejectedWrongReason {
                    actual: format!("fixture staging failed: {err}"),
                };
            }
        };
        classify_rejection(verify(&fixture, None), scenario.required_error_substr)
    }

    /// Pure classifier: given the verifier's result and the required named
    /// reason, decide the control verdict.
    pub(crate) fn classify_rejection(
        result: Result<(), String>,
        required_error_substr: &str,
    ) -> RejectionCheck {
        match result {
            Ok(()) => RejectionCheck::AcceptedButMustReject,
            Err(err) => {
                if err.contains(required_error_substr) {
                    RejectionCheck::RejectedAsExpected
                } else {
                    RejectionCheck::RejectedWrongReason { actual: err }
                }
            }
        }
    }

    /// Adjudicate the genuine positive control.
    pub(crate) fn adjudicate_genuine(dir: &Path) -> AcceptanceCheck {
        let fixture = match write_genuine(dir, BUNDLE_NODE_ID) {
            Ok(fixture) => fixture,
            Err(err) => {
                return AcceptanceCheck::RejectedButMustAccept {
                    actual: format!("genuine fixture staging failed: {err}"),
                };
            }
        };
        match verify(&fixture, None) {
            Ok(()) => AcceptanceCheck::AcceptedAsExpected,
            Err(err) => AcceptanceCheck::RejectedButMustAccept { actual: err },
        }
    }

    /// The (b) control: adjudicate the whole forgery corpus + the genuine
    /// positive control, and fold into a single [`StageOutcome`].
    ///
    /// Passes iff EVERY forgery is `RejectedAsExpected` AND the genuine bundle
    /// is `AcceptedAsExpected`.
    pub(crate) fn run_signed_bundle_control(dir: &Path) -> StageOutcome {
        let mut failures: Vec<String> = Vec::new();

        for scenario in SCENARIOS {
            let scenario_dir = dir.join(scenario.corpus_id);
            match adjudicate_scenario(&scenario_dir, scenario) {
                RejectionCheck::RejectedAsExpected => {}
                RejectionCheck::AcceptedButMustReject => failures.push(format!(
                    "{} ({}): FAIL-OPEN — forged bundle was ACCEPTED but must be rejected",
                    scenario.corpus_id, scenario.expected_rejection
                )),
                RejectionCheck::RejectedWrongReason { actual } => failures.push(format!(
                    "{} ({}): rejected for the WRONG reason — expected {:?}, got {:?}",
                    scenario.corpus_id,
                    scenario.expected_rejection,
                    scenario.required_error_substr,
                    actual
                )),
            }
        }

        match adjudicate_genuine(&dir.join("genuine")) {
            AcceptanceCheck::AcceptedAsExpected => {}
            AcceptanceCheck::RejectedButMustAccept { actual } => failures.push(format!(
                "positive control: genuine bundle was REJECTED but must be accepted: {actual}"
            )),
        }

        if failures.is_empty() {
            StageOutcome::Passed
        } else {
            StageOutcome::Failed(format!(
                "signed-bundle negative control: {} of {} check(s) failed: {}",
                failures.len(),
                SCENARIOS.len() + 1,
                failures.join("; ")
            ))
        }
    }

    // ── (d) wrong-node substitution ─────────────────────────────────────────

    /// Classification of the wrong-node substitution control.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) enum WrongNodeCheck {
        /// A substituted node id was rejected AND the matching id accepted.
        RejectedSubstitutionAcceptedMatch,
        /// The substituted node id was ACCEPTED — a fail-open. Control FAILS.
        AcceptedSubstitution,
        /// The substitution was rejected, but not for the node-id mismatch
        /// reason (guard: wrong reason is not a pass).
        RejectedWrongReason { actual: String },
        /// The matching id was rejected — the positive control is broken.
        MatchRejected { actual: String },
    }

    impl WrongNodeCheck {
        pub(crate) fn is_control_pass(&self) -> bool {
            matches!(self, WrongNodeCheck::RejectedSubstitutionAcceptedMatch)
        }
    }

    /// Pure classifier for the wrong-node control given both verifier results.
    pub(crate) fn classify_wrong_node(
        substituted: Result<(), String>,
        matching: Result<(), String>,
    ) -> WrongNodeCheck {
        match substituted {
            Ok(()) => WrongNodeCheck::AcceptedSubstitution,
            Err(err) if err.contains("node_id mismatch") => match matching {
                Ok(()) => WrongNodeCheck::RejectedSubstitutionAcceptedMatch,
                Err(actual) => WrongNodeCheck::MatchRejected { actual },
            },
            Err(actual) => WrongNodeCheck::RejectedWrongReason { actual },
        }
    }

    /// The (d) control: a genuine bundle minted for [`BUNDLE_NODE_ID`] must be
    /// REJECTED when verified against a *different* `expected_node_id`
    /// (substituted node) and ACCEPTED against its own id (positive control).
    ///
    /// NOTE (orchestrator threading — now landed; live proof deferred): this
    /// control adjudicates the assignment-VERIFY path
    /// (`assignment verify --expected-node-id`). The complementary
    /// orchestrator-level §4.7 challenge is now wired into every typed role
    /// validator (`node_adapter::enforce_identity_challenge`), so a substituted
    /// node also fails the validator itself — proven at the dispatch level by
    /// `node_adapter::tests::challenge_gate_rejects_substituted_node_*` and
    /// bound to this classifier by
    /// `classifier_binds_to_the_orchestrator_identity_challenge_error`. The
    /// remaining follow-on is the LIVE substituted-node stage run on a real
    /// guest (deferred to the Step-B live-verification phase, alongside the
    /// other T5 live proofs).
    pub(crate) fn run_wrong_node_control(dir: &Path) -> StageOutcome {
        let fixture = match write_genuine(dir, BUNDLE_NODE_ID) {
            Ok(fixture) => fixture,
            Err(err) => {
                return StageOutcome::Failed(format!(
                    "wrong-node negative control: fixture staging failed: {err}"
                ));
            }
        };
        let substituted = verify(&fixture, Some("nc-node-substituted-imposter"));
        let matching = verify(&fixture, Some(BUNDLE_NODE_ID));
        match classify_wrong_node(substituted, matching) {
            WrongNodeCheck::RejectedSubstitutionAcceptedMatch => StageOutcome::Passed,
            WrongNodeCheck::AcceptedSubstitution => StageOutcome::Failed(
                "wrong-node negative control: FAIL-OPEN — a bundle for a different node_id was \
                 ACCEPTED under a substituted expected_node_id"
                    .to_owned(),
            ),
            WrongNodeCheck::RejectedWrongReason { actual } => StageOutcome::Failed(format!(
                "wrong-node negative control: substituted node rejected for the WRONG reason \
                 (expected a node_id mismatch): {actual}"
            )),
            WrongNodeCheck::MatchRejected { actual } => StageOutcome::Failed(format!(
                "wrong-node negative control: positive control broken — the matching node_id was \
                 REJECTED: {actual}"
            )),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn tempdir(label: &str) -> PathBuf {
            let dir = std::env::temp_dir().join(format!(
                "rustynet-nc-signed-bundle-{label}-{}-{}",
                std::process::id(),
                unix_now()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            dir
        }

        #[test]
        fn genuine_bundle_is_accepted_positive_control() {
            let dir = tempdir("genuine");
            assert_eq!(
                adjudicate_genuine(&dir),
                AcceptanceCheck::AcceptedAsExpected
            );
            let _ = std::fs::remove_dir_all(&dir);
        }

        #[test]
        fn every_forgery_is_rejected_for_its_named_reason() {
            for scenario in SCENARIOS {
                let dir = tempdir(scenario.corpus_id);
                let check = adjudicate_scenario(&dir, scenario);
                assert_eq!(
                    check,
                    RejectionCheck::RejectedAsExpected,
                    "scenario {} must be rejected fail-closed for {:?}, got {:?}",
                    scenario.corpus_id,
                    scenario.required_error_substr,
                    check
                );
                let _ = std::fs::remove_dir_all(&dir);
            }
        }

        #[test]
        fn scenario_taxonomy_mirrors_the_live_signed_state_chaos_corpus() {
            // The `live_signed_state_chaos` corpus lives in a *bin* module
            // (`src/bin/live_signed_state_chaos/mod.rs`), which the library
            // crate cannot import — so the corpus contract is pinned here as
            // the reviewed `(id, expected_rejection)` set and this test binds
            // the assignment-scoped forgery set to it. If the corpus
            // `ALL_SCENARIOS` ever changes, update this pin in lockstep.
            const CORPUS: &[(&str, &str)] = &[
                ("truncated_one_byte", "malformed_truncated_one_byte"),
                ("truncated_half_length", "malformed_truncated_half_length"),
                ("future_dated_assignment", "future_dated_signed_state"),
                ("forged_signature_attempt", "unauthorised_signature"),
                (
                    "replay_watermarked_membership",
                    "replay_watermark_regression",
                ),
                ("quorum_starved_update", "partial_quorum_not_accepted"),
            ];
            for scenario in SCENARIOS {
                let (_, expected) = CORPUS
                    .iter()
                    .find(|(id, _)| *id == scenario.corpus_id)
                    .unwrap_or_else(|| {
                        panic!("scenario {} is not in the corpus", scenario.corpus_id)
                    });
                assert_eq!(
                    *expected, scenario.expected_rejection,
                    "scenario {} must reuse the corpus expected_rejection label",
                    scenario.corpus_id
                );
            }
            // Every corpus scenario is covered EXCEPT the documented
            // membership-only quorum case — so the assignment control cannot
            // silently drop coverage without this test noticing.
            let covered: std::collections::BTreeSet<&str> =
                SCENARIOS.iter().map(|s| s.corpus_id).collect();
            let uncovered: Vec<&str> = CORPUS
                .iter()
                .map(|(id, _)| *id)
                .filter(|id| !covered.contains(id))
                .collect();
            assert_eq!(
                uncovered,
                vec!["quorum_starved_update"],
                "the only corpus scenario the assignment verifier does not adjudicate is the \
                 membership-layer quorum case"
            );
        }

        #[test]
        fn guard_a_fail_open_accept_fails_the_control() {
            // If a "forgery" were actually accepted, the classifier must call
            // it a fail-open, never a pass.
            let check = classify_rejection(Ok(()), "future dated");
            assert_eq!(check, RejectionCheck::AcceptedButMustReject);
            assert!(!check.is_control_pass());
        }

        #[test]
        fn guard_a_wrong_reason_rejection_fails_the_control() {
            // Rejected, but not for the named reason ⇒ NOT a control pass. This
            // is the exact corruption the spec forbids: loosening "what counts
            // as a rejection".
            let check = classify_rejection(
                Err("auto-tunnel bundle is stale".to_owned()),
                "future dated",
            );
            assert!(matches!(check, RejectionCheck::RejectedWrongReason { .. }));
            assert!(!check.is_control_pass());
        }

        #[test]
        fn signed_bundle_control_passes_end_to_end() {
            let dir = tempdir("control-pass");
            assert_eq!(run_signed_bundle_control(&dir), StageOutcome::Passed);
            let _ = std::fs::remove_dir_all(&dir);
        }

        #[test]
        fn wrong_node_control_passes_end_to_end() {
            let dir = tempdir("wrong-node-pass");
            assert_eq!(run_wrong_node_control(&dir), StageOutcome::Passed);
            let _ = std::fs::remove_dir_all(&dir);
        }

        #[test]
        fn wrong_node_classifier_rejects_fail_open_and_wrong_reason() {
            // Substituted node accepted ⇒ fail-open ⇒ control fails.
            assert_eq!(
                classify_wrong_node(Ok(()), Ok(())),
                WrongNodeCheck::AcceptedSubstitution
            );
            // Substituted node rejected for some OTHER reason ⇒ not a pass.
            assert!(matches!(
                classify_wrong_node(
                    Err("auto-tunnel signature verification failed".to_owned()),
                    Ok(())
                ),
                WrongNodeCheck::RejectedWrongReason { .. }
            ));
            // Correct mismatch rejection + matching accept ⇒ control passes.
            assert_eq!(
                classify_wrong_node(
                    Err("assignment bundle node_id mismatch: expected a, got b".to_owned()),
                    Ok(())
                ),
                WrongNodeCheck::RejectedSubstitutionAcceptedMatch
            );
            // Correct mismatch but the matching positive control is broken.
            assert!(matches!(
                classify_wrong_node(
                    Err("assignment bundle node_id mismatch: expected a, got b".to_owned()),
                    Err("something".to_owned())
                ),
                WrongNodeCheck::MatchRejected { .. }
            ));
        }

        #[test]
        fn classifier_binds_to_the_orchestrator_identity_challenge_error() {
            // The wrong-node control adjudicates the assignment-VERIFY path. The
            // orchestrator's §4.7 role-validator challenge is a SECOND mechanism
            // (see node_adapter::enforce_identity_challenge): a substituted node
            // makes the live daemon report its own id, which the adjudicator
            // rejects. Prove that challenge error, as a string, is classified as
            // a correct substitution rejection here too — so the two mechanisms
            // stay bound and a future rename of either error cannot silently
            // downgrade the T5 verdict to RejectedWrongReason.
            use crate::vm_lab::orchestrator::role_validation::identity_challenge::{
                IdentityEvidence, adjudicate_identity,
            };
            let substituted = adjudicate_identity(
                Some("nc-node-substituted-imposter"),
                &IdentityEvidence::live("real-node"),
            )
            .map_err(|e| e.to_string());
            assert!(substituted.is_err());
            assert_eq!(
                classify_wrong_node(substituted, Ok(())),
                WrongNodeCheck::RejectedSubstitutionAcceptedMatch
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_ids_and_names_match_the_catalog() {
        assert_eq!(
            NegativeControlSignedBundleRejectionStage.id(),
            StageId::NegativeControlSignedBundleRejection
        );
        assert_eq!(
            NegativeControlSignedBundleRejectionStage.name(),
            "negative_control_signed_bundle_rejection"
        );
        assert_eq!(
            NegativeControlPlantedResidueStage.id(),
            StageId::NegativeControlPlantedResidue
        );
        assert_eq!(
            NegativeControlWrongNodeSubstitutionStage.id(),
            StageId::NegativeControlWrongNodeSubstitution
        );
        assert_eq!(
            NegativeControlDaemonKillMidStageStage.id(),
            StageId::NegativeControlDaemonKillMidStage
        );
    }

    #[test]
    fn controls_carry_no_dependencies_and_run_once() {
        for (deps, fanout) in [
            (
                NegativeControlSignedBundleRejectionStage.dependencies(),
                NegativeControlSignedBundleRejectionStage.fanout(),
            ),
            (
                NegativeControlPlantedResidueStage.dependencies(),
                NegativeControlPlantedResidueStage.fanout(),
            ),
        ] {
            assert!(deps.is_empty());
            assert_eq!(fanout, StageFanout::Once);
        }
    }

    // ── (a) planted-residue adjudication ─────────────────────────────────────

    #[test]
    fn planted_residue_dirty_probe_is_detected_control_passes() {
        // Each planted-residue dimension the probe reports must be caught.
        for dirty in [
            "nft=rustynet_boot, daemon=down iface=-", // leftover killswitch table
            "nft=- daemon=up iface=-",                // daemon still running
            "nft=- daemon=down iface=rustynet0,",     // leftover interface
            "nft=rustynet_g1, daemon=up iface=rustynet0,", // all three
        ] {
            let outcome = adjudicate_planted_residue(dirty);
            assert!(
                outcome.is_control_pass(),
                "planted residue {dirty:?} must be detected (control passes), got {outcome:?}"
            );
        }
    }

    #[test]
    fn planted_residue_unverifiable_probe_is_detected_fail_closed() {
        // A garbled/truncated probe (fail-closed) must also read as dirty, so
        // the control passes: an unverifiable node is never treated clean.
        assert!(adjudicate_planted_residue("garbled noise no tokens").is_control_pass());
        assert!(adjudicate_planted_residue("nft=unknown daemon=down iface=-").is_control_pass());
    }

    #[test]
    fn guard_a_genuinely_clean_probe_is_a_control_fail_not_a_pass() {
        // The residue control's job is to catch a probe that PASSES a
        // residue-carrying node. A genuinely clean probe (which the parser
        // correctly passes) means "no residue was planted / detected" ⇒ the
        // control did NOT observe the target failing ⇒ control FAILS. This
        // pins that the adjudicator is not vacuously "always pass".
        let outcome = adjudicate_planted_residue("nft=- daemon=down iface=-\n");
        assert_eq!(outcome, ResidueControlOutcome::FailOpenResidueMissed);
        assert!(!outcome.is_control_pass());
    }

    // ── (c) daemon-kill adjudication ─────────────────────────────────────────

    #[test]
    fn daemon_kill_non_pass_outcomes_pass_the_control() {
        for recorded in [
            StageOutcome::Failed("daemon killed".to_owned()),
            StageOutcome::Skipped,
            StageOutcome::NotRun,
            StageOutcome::Reused {
                evidence_sha256: "abc".to_owned(),
            },
        ] {
            assert!(
                adjudicate_daemon_kill_outcome(&recorded).is_control_pass(),
                "a {recorded:?} under a mid-stage kill must satisfy the control"
            );
        }
    }

    #[test]
    fn guard_c_a_pass_under_kill_is_a_false_green_control_fails() {
        let outcome = adjudicate_daemon_kill_outcome(&StageOutcome::Passed);
        assert_eq!(outcome, KillControlOutcome::FalseGreenUnderKill);
        assert!(!outcome.is_control_pass());
    }
}
