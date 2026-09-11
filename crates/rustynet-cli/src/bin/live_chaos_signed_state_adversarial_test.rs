#![forbid(unsafe_code)]

//! Live-lab chaos stage: signed-state adversarial sweep.
//!
//! Audit I2 (2026-09-11) finding 1: this stage used to be VACUOUS — it
//! generated fixture files and "validated" them with its own twin generator,
//! so no rustynet code ever ran and a build with no replay/forgery/freshness
//! rejection at all would have passed this T4Security stage.
//!
//! The sweep now drives the *real* production signed-state funnel —
//! [`rustynet_control::membership::decode_signed_update`] and
//! [`rustynet_control::membership::apply_signed_update`], the exact path the
//! daemon runs before any membership state is mutated — with one adversarial
//! case per fixture scenario and asserts every one is rejected fail-closed,
//! with the rejection reason matching the class the fixture targets. The
//! fixture manifest stays in the report as artifact metadata; the verdict
//! comes only from the product.
//!
//! Scope honesty: every scenario in the corpus reaches its intended control
//! in-process (malformed decode, forged signature, quorum starvation,
//! future-dating, and replay via a pre-seeded watermark cache), so no fixture
//! needs live re-scoping against a running daemon. The whole battery is built
//! from throwaway in-process Ed25519 keys against a synthetic membership
//! network; it touches no production key, file, or state.

mod live_chaos_support;
mod live_signed_state_chaos;

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use live_chaos_support::{ChaosStage, git_head_commit, repo_root, unix_now};
use live_signed_state_chaos::{
    ValidatedScenario, generate_manifest, selected_scenarios, validate_manifest, write_manifest,
};
use rustynet_control::membership::{
    MEMBERSHIP_SCHEMA_VERSION, MembershipApprover, MembershipApproverRole,
    MembershipApproverStatus, MembershipNode, MembershipNodeStatus, MembershipOperation,
    MembershipReplayCache, MembershipSignature, MembershipState, MembershipUpdateRecord,
    SignedMembershipUpdate, apply_signed_update, decode_signed_update, encode_signed_update,
    preview_next_state, sign_update_record,
};
use rustynet_control::roles::RoleCapability;
use serde_json::{Value, json};

const CATEGORY: &str = "chaos_signed_state_adversarial";

/// Synthetic network id — never collides with any real deployment.
const CHAOS_NETWORK_ID: &str = "chaos-signed-state-net";
/// Fixed evaluation clock so freshness checks are deterministic.
const CHAOS_NOW_UNIX: u64 = 1_000_000;

fn signed_state_stages() -> Vec<ChaosStage> {
    vec![
        ChaosStage {
            name: "chaos_replay_old_membership",
            fault: "inject older validly-signed membership update with stale watermark",
            pass_criterion: "replay rejected by the production verifier and state stays on the current epoch",
            recovery_deadline_secs: 60,
        },
        ChaosStage {
            name: "chaos_future_dated_assignment",
            fault: "inject assignment bundle generated beyond allowed clock skew",
            pass_criterion: "future bundle rejected by the production verifier and existing assignment remains active",
            recovery_deadline_secs: 60,
        },
        ChaosStage {
            name: "chaos_malformed_bundle_truncation",
            fault: "submit truncated signed-state bundle variants",
            pass_criterion: "all malformed variants fail closed in the production decoder with structured errors and no panic",
            recovery_deadline_secs: 60,
        },
        ChaosStage {
            name: "chaos_forged_signature_attempt",
            fault: "submit bundle signed by unauthorised key material",
            pass_criterion: "signature verification fails in the production verifier and no state mutation occurs",
            recovery_deadline_secs: 60,
        },
        ChaosStage {
            name: "chaos_quorum_starvation_propose",
            fault: "submit quorum-governed update without enough approvals",
            pass_criterion: "partial-quorum update is rejected by the production verifier and no mutation is accepted",
            recovery_deadline_secs: 60,
        },
    ]
}

#[derive(Clone, Debug)]
struct Config {
    report_path: PathBuf,
    log_path: PathBuf,
    fixture_dir: PathBuf,
    git_commit: String,
    dry_run: bool,
    scenario: String,
}

impl Config {
    fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let root = repo_root()?;
        let mut config = Self {
            report_path: root.join(format!("artifacts/phase10/{CATEGORY}_report.json")),
            log_path: root.join(format!("artifacts/phase10/source/{CATEGORY}.log")),
            fixture_dir: root.join("artifacts/phase10/chaos_signed_state_fixtures"),
            git_commit: env::var("RUSTYNET_EXPECTED_GIT_COMMIT")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| git_head_commit(&root)),
            dry_run: false,
            scenario: "all".to_owned(),
        };

        let args = args.into_iter().collect::<Vec<_>>();
        let mut idx = 0usize;
        while idx < args.len() {
            match args[idx].as_str() {
                "--dry-run" => config.dry_run = true,
                "--report-path" => {
                    idx += 1;
                    config.report_path =
                        PathBuf::from(required_value(&args, idx, "--report-path")?);
                }
                "--log-path" => {
                    idx += 1;
                    config.log_path = PathBuf::from(required_value(&args, idx, "--log-path")?);
                }
                "--fixture-dir" => {
                    idx += 1;
                    config.fixture_dir =
                        PathBuf::from(required_value(&args, idx, "--fixture-dir")?);
                }
                "--git-commit" => {
                    idx += 1;
                    config.git_commit = required_value(&args, idx, "--git-commit")?;
                }
                "--scenario" => {
                    idx += 1;
                    config.scenario = required_value(&args, idx, "--scenario")?;
                }
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                other => {
                    print_usage();
                    return Err(format!("unknown argument: {other}"));
                }
            }
            idx += 1;
        }
        Ok(config)
    }
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let config = Config::parse(env::args().skip(1))?;
    write_parent(&config.log_path)?;
    fs::write(
        &config.log_path,
        format!(
            "category={CATEGORY}\ndry_run={}\ngenerated_at_unix={}\nfixture_dir={}\n",
            config.dry_run,
            unix_now(),
            config.fixture_dir.display()
        ),
    )
    .map_err(|err| format!("write {} failed: {err}", config.log_path.display()))?;

    // The fixture manifest stays as artifact metadata: it pins the corpus and
    // the expected rejection labels, but it no longer decides the verdict.
    let manifest = generate_manifest(&config.fixture_dir, &config.scenario, unix_now())?;
    let manifest_path = write_manifest(&config.fixture_dir, &manifest)?;
    let validated = validate_manifest(&manifest)?;

    let cases = funnel_cases(&config.scenario)?;
    // Fail closed on any corpus/verifier drift: every generated fixture must
    // have a real-funnel case with the same id, and vice versa.
    let manifest_ids: Vec<&str> = validated.iter().map(|s| s.id.as_str()).collect();
    let case_ids: Vec<&str> = cases.iter().map(|case| case.id).collect();
    if manifest_ids != case_ids {
        return Err(format!(
            "signed-state fixture corpus and verifier case set diverge: fixtures={manifest_ids:?} cases={case_ids:?}"
        ));
    }

    let outcomes: Vec<CaseOutcome> = cases.iter().map(evaluate).collect();
    let all_passed = outcomes.iter().all(|outcome| outcome.passed);
    let accepted_count = outcomes.iter().filter(|outcome| !outcome.rejected).count();

    write_log(&config, &outcomes)?;

    let report = render_report(&config, &manifest_path, &validated, &outcomes, all_passed);
    write_parent(&config.report_path)?;
    fs::write(
        &config.report_path,
        serde_json::to_string_pretty(&report)
            .map_err(|err| format!("serialise signed-state chaos report failed: {err}"))?,
    )
    .map_err(|err| format!("write {} failed: {err}", config.report_path.display()))?;

    if all_passed {
        Ok(())
    } else {
        Err(format!(
            "signed-state adversarial sweep failed: {} of {} cases not rejected as expected ({} accepted by the production verifier)",
            outcomes.iter().filter(|outcome| !outcome.passed).count(),
            outcomes.len(),
            accepted_count,
        ))
    }
}

/// Which production entry point a case drives.
enum FunnelPath {
    /// Run a forged [`SignedMembershipUpdate`] through `apply_signed_update`.
    Apply {
        signed: Box<SignedMembershipUpdate>,
        /// Pre-seed the replay cache so the case reaches
        /// `replay_cache.observe` (watermark/replay class). `None` means a
        /// fresh cache.
        preseed_replay: Option<(String, u64)>,
    },
    /// Hand a raw (malformed/truncated/empty) envelope string to
    /// `decode_signed_update`.
    Decode { raw: String },
}

/// One adversarial case driven through the production verifier. The
/// `expected_rejection` label is the corpus label (kept in the report for
/// cross-referencing with the fixture manifest); the verdict additionally
/// requires the rejection reason to match `expect_reason_contains`, so we
/// assert the *right* control rejected (not an unrelated error).
struct FunnelCase {
    id: &'static str,
    stage_name: &'static str,
    expected_rejection: &'static str,
    expect_reason_contains: &'static str,
    rationale: &'static str,
    path: FunnelPath,
}

/// Lowercase hex encode (no external `hex` dep in this bin).
fn hex_lower(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(LUT[(byte >> 4) as usize] as char);
        out.push(LUT[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Deterministic in-process signing key from a single seed byte.
fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// Public-key hex for an in-process key (32-byte verifying key).
fn pubkey_hex(seed: u8) -> String {
    hex_lower(key(seed).verifying_key().as_bytes())
}

fn approver(id: &str, seed: u8, role: MembershipApproverRole) -> MembershipApprover {
    MembershipApprover {
        approver_id: id.to_owned(),
        approver_pubkey_hex: pubkey_hex(seed),
        role,
        status: MembershipApproverStatus::Active,
        created_at_unix: 100,
    }
}

fn active_node(node_id: &str, pubkey_byte: u8) -> MembershipNode {
    MembershipNode {
        node_id: node_id.to_owned(),
        node_pubkey_hex: hex_lower(&[pubkey_byte; 32]),
        owner: "chaos-owner@example.local".to_owned(),
        status: MembershipNodeStatus::Active,
        roles: vec!["tag:servers".to_owned()],
        capabilities: vec![RoleCapability::Anchor],
        joined_at_unix: 100,
        updated_at_unix: 100,
    }
}

/// The self-contained synthetic network the whole sweep runs against: one node,
/// an owner approver (key seed 1) plus two guardian approvers (seeds 2/3),
/// quorum threshold 2.
fn synthetic_state() -> MembershipState {
    MembershipState {
        schema_version: MEMBERSHIP_SCHEMA_VERSION,
        network_id: CHAOS_NETWORK_ID.to_owned(),
        epoch: 1,
        nodes: vec![active_node("node-a", 9)],
        approver_set: vec![
            approver("owner-1", 1, MembershipApproverRole::Owner),
            approver("guardian-1", 2, MembershipApproverRole::Guardian),
            approver("guardian-2", 3, MembershipApproverRole::Guardian),
        ],
        quorum_threshold: 2,
        metadata_hash: None,
        tombstones: Vec::new(),
    }
}

/// A legitimate `SetNodeCapabilities` operation on the synthetic network.
fn valid_operation() -> MembershipOperation {
    MembershipOperation::SetNodeCapabilities {
        node_id: "node-a".to_owned(),
        capabilities: vec![RoleCapability::Anchor, RoleCapability::Client],
    }
}

/// Build the canonical, *correct* update record: correct prev/new state roots,
/// epoch chain, and freshness. This is the honest baseline every forged case
/// is derived from, so a forged case reaches its intended rejection rather
/// than tripping an earlier check.
fn valid_record(update_id: &str) -> Result<(MembershipState, MembershipUpdateRecord), String> {
    let state = synthetic_state();
    let operation = valid_operation();
    let next = preview_next_state(&state, &operation, CHAOS_NOW_UNIX - 10)
        .map_err(|err| format!("preview_next_state failed: {err}"))?;
    let prev_root = state
        .state_root_hex()
        .map_err(|err| format!("prev state root failed: {err}"))?;
    let new_root = next
        .state_root_hex()
        .map_err(|err| format!("new state root failed: {err}"))?;
    let record = MembershipUpdateRecord {
        network_id: state.network_id.clone(),
        update_id: update_id.to_owned(),
        operation,
        target: "node-a".to_owned(),
        prev_state_root: prev_root,
        new_state_root: new_root,
        epoch_prev: state.epoch,
        epoch_new: state.epoch + 1,
        created_at_unix: CHAOS_NOW_UNIX - 10,
        expires_at_unix: CHAOS_NOW_UNIX + 600,
        reason_code: "chaos".to_owned(),
        policy_context: None,
    };
    Ok((state, record))
}

/// Sign `record` with the in-process owner and guardian-1 keys (quorum 2,
/// owner present) — the canonical valid signature set.
fn quorum_signatures(record: &MembershipUpdateRecord) -> Result<Vec<MembershipSignature>, String> {
    Ok(vec![
        sign_update_record(record, "owner-1", &key(1))
            .map_err(|err| format!("owner sign failed: {err}"))?,
        sign_update_record(record, "guardian-1", &key(2))
            .map_err(|err| format!("guardian sign failed: {err}"))?,
    ])
}

/// Build a fully valid signed update (used by the accept-control test and as
/// the basis for replay forgery).
fn valid_signed_update(update_id: &str) -> Result<SignedMembershipUpdate, String> {
    let (_state, record) = valid_record(update_id)?;
    let signatures = quorum_signatures(&record)?;
    Ok(SignedMembershipUpdate {
        record,
        approver_signatures: signatures,
    })
}

/// Assemble one adversarial case per corpus scenario id, engineered so the
/// earlier checks in `apply_signed_update` pass and execution reaches the one
/// control the fixture targets. Case ids MUST equal the fixture corpus ids —
/// `run` fails closed if the two sets ever diverge.
fn funnel_cases(scenario: &str) -> Result<Vec<FunnelCase>, String> {
    let selected = selected_scenarios(scenario)?;
    let mut cases = Vec::new();
    for scenario in selected {
        let case = match scenario.id {
            "truncated_one_byte" => FunnelCase {
                id: scenario.id,
                stage_name: scenario.stage_name,
                expected_rejection: scenario.expected_rejection,
                expect_reason_contains: "invalid membership format",
                rationale: "a single-byte envelope cannot be decoded (default-deny on malformed input)",
                path: FunnelPath::Decode {
                    raw: "{".to_owned(),
                },
            },
            "truncated_half_length" => {
                let signed = valid_signed_update("update-truncated-half")?;
                let envelope = encode_signed_update(&signed)
                    .map_err(|err| format!("encode envelope failed: {err}"))?;
                FunnelCase {
                    id: scenario.id,
                    stage_name: scenario.stage_name,
                    expected_rejection: scenario.expected_rejection,
                    expect_reason_contains: "invalid membership format",
                    rationale: "a half-truncated envelope cannot be decoded into a signed update",
                    path: FunnelPath::Decode {
                        raw: envelope[..envelope.len() / 2].to_owned(),
                    },
                }
            }
            "future_dated_assignment" => {
                let (_state, mut record) = valid_record("update-future-dated")?;
                record.created_at_unix = CHAOS_NOW_UNIX + 3600;
                // Keep expires_at_unix strictly greater than created_at_unix
                // so the canonical-payload invariant holds and the freshness
                // check is reached.
                record.expires_at_unix = record.created_at_unix + 600;
                let signatures = quorum_signatures(&record)?;
                FunnelCase {
                    id: scenario.id,
                    stage_name: scenario.stage_name,
                    expected_rejection: scenario.expected_rejection,
                    expect_reason_contains: "future dated",
                    rationale: "an update created beyond the clock-skew window is rejected",
                    path: FunnelPath::Apply {
                        signed: Box::new(SignedMembershipUpdate {
                            record,
                            approver_signatures: signatures,
                        }),
                        preseed_replay: None,
                    },
                }
            }
            "forged_signature_attempt" => {
                let (_state, record) = valid_record("update-forged-sig")?;
                let mut signatures = quorum_signatures(&record)?;
                // Flip the leading hex nibble of the owner signature.
                let sig = &mut signatures[0].signature_hex;
                let flipped = if sig.starts_with('f') { "0" } else { "f" };
                sig.replace_range(0..1, flipped);
                FunnelCase {
                    id: scenario.id,
                    stage_name: scenario.stage_name,
                    expected_rejection: scenario.expected_rejection,
                    expect_reason_contains: "signature verification failed",
                    rationale: "a tampered signature must fail strict Ed25519 verification",
                    path: FunnelPath::Apply {
                        signed: Box::new(SignedMembershipUpdate {
                            record,
                            approver_signatures: signatures,
                        }),
                        preseed_replay: None,
                    },
                }
            }
            "replay_watermarked_membership" => {
                let signed = valid_signed_update("update-replayed")?;
                let update_id = signed.record.update_id.clone();
                let epoch_new = signed.record.epoch_new;
                FunnelCase {
                    id: scenario.id,
                    stage_name: scenario.stage_name,
                    expected_rejection: scenario.expected_rejection,
                    expect_reason_contains: "membership replay detected",
                    rationale: "a previously-observed update id (stale watermark) is rejected",
                    path: FunnelPath::Apply {
                        signed: Box::new(signed),
                        preseed_replay: Some((update_id, epoch_new)),
                    },
                }
            }
            "quorum_starved_update" => {
                let (_state, record) = valid_record("update-below-threshold")?;
                let owner_sig = sign_update_record(&record, "owner-1", &key(1))
                    .map_err(|err| format!("owner sign failed: {err}"))?;
                FunnelCase {
                    id: scenario.id,
                    stage_name: scenario.stage_name,
                    expected_rejection: scenario.expected_rejection,
                    expect_reason_contains: "threshold signature requirements not met",
                    rationale: "fewer signatures than the quorum threshold is rejected",
                    path: FunnelPath::Apply {
                        signed: Box::new(SignedMembershipUpdate {
                            record,
                            approver_signatures: vec![owner_sig],
                        }),
                        preseed_replay: None,
                    },
                }
            }
            other => {
                return Err(format!(
                    "no production-verifier case exists for corpus scenario {other}; add one instead of self-validating"
                ));
            }
        };
        cases.push(case);
    }
    Ok(cases)
}

/// Outcome of driving one case through the production verifier.
struct CaseOutcome {
    id: &'static str,
    stage_name: &'static str,
    rejected: bool,
    reason: String,
    expected_rejection: &'static str,
    expect_reason_contains: &'static str,
    reason_matches: bool,
    rationale: &'static str,
    passed: bool,
}

/// Evaluate a case through the production rejection path. For `Apply` cases
/// the forged update runs through `apply_signed_update` against the synthetic
/// state; for `Decode` cases the raw payload runs through
/// `decode_signed_update`. Either way an (unexpected) accept performs no
/// production mutation — the state is fully synthetic and in-memory.
fn evaluate(case: &FunnelCase) -> CaseOutcome {
    let (rejected, reason) = match &case.path {
        FunnelPath::Apply {
            signed,
            preseed_replay,
        } => {
            let state = synthetic_state();
            let mut cache = MembershipReplayCache::default();
            if let Some((update_id, epoch_new)) = preseed_replay {
                let _ = cache.observe(update_id, *epoch_new);
            }
            match apply_signed_update(&state, signed, CHAOS_NOW_UNIX, &mut cache) {
                Ok(_) => (
                    false,
                    "ACCEPTED: verifier applied an adversarial update".to_owned(),
                ),
                Err(err) => (true, err.to_string()),
            }
        }
        FunnelPath::Decode { raw } => match decode_signed_update(raw) {
            Ok(_) => (
                false,
                "ACCEPTED: decoder accepted a malformed envelope".to_owned(),
            ),
            Err(err) => (true, err.to_string()),
        },
    };
    let reason_matches = reason
        .to_lowercase()
        .contains(&case.expect_reason_contains.to_lowercase());
    let passed = rejected && reason_matches;
    CaseOutcome {
        id: case.id,
        stage_name: case.stage_name,
        rejected,
        reason,
        expected_rejection: case.expected_rejection,
        expect_reason_contains: case.expect_reason_contains,
        reason_matches,
        rationale: case.rationale,
        passed,
    }
}

/// A stage passes only when it has at least one evaluated case and every case
/// was rejected with the expected reason class.
fn stage_status(stage_outcomes: &[&CaseOutcome]) -> &'static str {
    if stage_outcomes.is_empty() || !stage_outcomes.iter().all(|outcome| outcome.passed) {
        "fail"
    } else {
        "pass"
    }
}

fn write_log(config: &Config, outcomes: &[CaseOutcome]) -> Result<(), String> {
    write_parent(&config.log_path)?;
    let mut body = format!(
        "category={CATEGORY}\ndry_run={}\ngenerated_at_unix={}\ncase_count={}\n",
        config.dry_run,
        unix_now(),
        outcomes.len(),
    );
    for outcome in outcomes {
        body.push_str(&format!(
            "case={} stage={} rejected={} reason_matches={} passed={} reason={}\n",
            outcome.id,
            outcome.stage_name,
            outcome.rejected,
            outcome.reason_matches,
            outcome.passed,
            outcome.reason,
        ));
    }
    fs::write(&config.log_path, body)
        .map_err(|err| format!("write {} failed: {err}", config.log_path.display()))
}

fn render_report(
    config: &Config,
    manifest_path: &Path,
    validated: &[ValidatedScenario],
    outcomes: &[CaseOutcome],
    all_passed: bool,
) -> Value {
    let bytes_by_id: BTreeMap<&str, u64> = validated
        .iter()
        .map(|scenario| (scenario.id.as_str(), scenario.bytes))
        .collect();
    let grouped = group_by_stage(outcomes);
    let stage_reports = signed_state_stages()
        .iter()
        .map(|stage| {
            let empty: Vec<&CaseOutcome> = Vec::new();
            let stage_outcomes: Vec<&CaseOutcome> =
                grouped.get(stage.name).cloned().unwrap_or(empty);
            let scenario_values = stage_outcomes
                .iter()
                .map(|outcome| {
                    json!({
                        "scenario": outcome.id,
                        "bytes": bytes_by_id.get(outcome.id).copied().unwrap_or(0),
                        "expected_rejection": outcome.expected_rejection,
                        "expected_reason_contains": outcome.expect_reason_contains,
                        "rejected": outcome.rejected,
                        "reason": outcome.reason,
                        "rationale": outcome.rationale,
                        "status": if outcome.passed { "pass" } else { "fail" },
                    })
                })
                .collect::<Vec<_>>();
            json!({
                "name": stage.name,
                "status": stage_status(&stage_outcomes),
                "fault": stage.fault,
                "pass_criterion": stage.pass_criterion,
                "recovery_deadline_secs": stage.recovery_deadline_secs,
                "measured_recovery_secs": 0,
                "plaintext_leak_check": "not-applicable-offline",
                "production_state_mutation": false,
                "expected_result": "reject_fail_closed",
                "verifier_case_count": stage_outcomes.len(),
                "scenarios": scenario_values,
            })
        })
        .collect::<Vec<_>>();
    let accepted_count = outcomes.iter().filter(|outcome| !outcome.rejected).count();
    json!({
        "schema_version": 1,
        "suite": "rustynet-live-lab-chaos",
        "category": CATEGORY,
        "overall_status": if all_passed { "pass" } else { "fail" },
        "summary": "forged signed-state fixtures are driven through the production membership verifier (decode_signed_update/apply_signed_update); every case must be rejected fail-closed with the expected reason class",
        "dry_run": config.dry_run,
        "generated_at_unix": unix_now(),
        "git_commit": config.git_commit,
        "fixture_manifest": manifest_path,
        "fixture_scenario_count": validated.len(),
        "verifier_case_count": outcomes.len(),
        "stages": stage_reports,
        "security_invariants": {
            "requires_explicit_enable_chaos_suite": true,
            "requires_teardown_registration_before_injection": false,
            "requires_plaintext_leak_capture_for_live_faults": false,
            "production_state_mutation": false,
            "offline_only": true,
            "production_accepted": false,
            "expected_result": "reject_fail_closed",
            "drives_production_verifier": true,
            "verifier_rejects_all_forged_updates": all_passed,
            "no_forged_update_accepted": accepted_count == 0
        }
    })
}

fn group_by_stage(outcomes: &[CaseOutcome]) -> BTreeMap<String, Vec<&CaseOutcome>> {
    let mut grouped = BTreeMap::new();
    for outcome in outcomes {
        grouped
            .entry(outcome.stage_name.to_owned())
            .or_insert_with(Vec::new)
            .push(outcome);
    }
    grouped
}

fn required_value(args: &[String], idx: usize, flag: &str) -> Result<String, String> {
    args.get(idx)
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .ok_or_else(|| format!("missing required argument value for {flag}"))
}

fn print_usage() {
    eprintln!(
        "usage: {CATEGORY} [--dry-run] [--scenario all|<scenario>] [--fixture-dir <path>] [--report-path <path>] [--log-path <path>] [--git-commit <sha>]"
    );
}

fn write_parent(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("create {} failed: {err}", parent.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn test_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "rustynet-chaos-signed-state-{label}-{}",
            std::process::id()
        ))
    }

    fn parse(args: &[&str]) -> Result<Config, String> {
        Config::parse(args.iter().map(|value| (*value).to_owned()))
    }

    #[test]
    fn parser_accepts_dry_run_and_fixture_dir() {
        let config = parse(&[
            "--dry-run",
            "--fixture-dir",
            "/tmp/rustynet-signed-state-fixtures",
            "--scenario",
            "all",
        ])
        .expect("config should parse");
        assert!(config.dry_run);
        assert_eq!(config.scenario, "all");
    }

    // Audit I2 finding 1: the old bin "validated" fixtures with its own twin
    // generator and never ran rustynet code. These tests pin the replacement:
    // the production verifier rejects every case with the expected reason
    // class, and an update the verifier WOULD ACCEPT fails the stage.
    #[test]
    fn every_funnel_case_is_rejected_by_the_production_verifier() {
        let cases = funnel_cases("all").expect("cases should build");
        assert_eq!(cases.len(), 6, "one case per corpus scenario");
        for case in &cases {
            let outcome = evaluate(case);
            assert!(
                outcome.rejected,
                "case `{}` was ACCEPTED by the production verifier (reason={})",
                case.id, outcome.reason
            );
            assert!(
                outcome.reason_matches,
                "case `{}` rejected but reason did not contain `{}` (reason={})",
                case.id, case.expect_reason_contains, outcome.reason
            );
            assert!(outcome.passed, "case `{}` did not pass", case.id);
        }
    }

    #[test]
    fn funnel_cases_cover_signature_freshness_replay_and_malformed_classes() {
        let cases = funnel_cases("all").expect("cases should build");
        let by_id: BTreeMap<&str, &FunnelCase> = cases.iter().map(|case| (case.id, case)).collect();
        // malformed/decode class
        assert!(matches!(
            by_id["truncated_one_byte"].path,
            FunnelPath::Decode { .. }
        ));
        assert!(matches!(
            by_id["truncated_half_length"].path,
            FunnelPath::Decode { .. }
        ));
        // freshness class
        assert!(matches!(
            by_id["future_dated_assignment"].path,
            FunnelPath::Apply { .. }
        ));
        // signature class
        assert!(matches!(
            by_id["forged_signature_attempt"].path,
            FunnelPath::Apply { .. }
        ));
        // replay/watermark class
        let replay = by_id["replay_watermarked_membership"];
        assert!(matches!(
            &replay.path,
            FunnelPath::Apply {
                preseed_replay: Some(_),
                ..
            }
        ));
        // quorum class
        assert!(matches!(
            by_id["quorum_starved_update"].path,
            FunnelPath::Apply { .. }
        ));
    }

    // Mutation test: a fixture the product would ACCEPT must make the stage
    // fail. The verifier genuinely accepts this fully valid update; the stage
    // aggregation must therefore mark the case and its stage failed.
    #[test]
    fn a_product_accepted_update_fails_the_stage() {
        let signed = valid_signed_update("update-valid-control")
            .expect("a fully valid signed update should build");
        let case = FunnelCase {
            id: "valid_control_mutation",
            stage_name: "chaos_forged_signature_attempt",
            expected_rejection: "no_rejection_expected",
            expect_reason_contains: "this reason can never appear",
            rationale: "mutation control: the production verifier ACCEPTS this update",
            path: FunnelPath::Apply {
                signed: Box::new(signed),
                preseed_replay: None,
            },
        };
        let outcome = evaluate(&case);
        assert!(
            !outcome.rejected,
            "control update must be accepted by the verifier (reason={})",
            outcome.reason
        );
        assert!(!outcome.passed);
        assert_eq!(stage_status(&[&outcome]), "fail");
        // And the accepted count that fails the run is non-zero.
        assert_eq!(
            std::iter::once(&outcome)
                .filter(|outcome| !outcome.rejected)
                .count(),
            1
        );
    }

    // Load-bearing for the mutation test: prove the verifier is not rejecting
    // everything, so the rejections above are meaningful.
    #[test]
    fn verifier_accepts_a_valid_bundle_so_rejections_are_meaningful() {
        let signed = valid_signed_update("update-valid-control-2")
            .expect("a fully valid signed update should build");
        let state = synthetic_state();
        let mut cache = MembershipReplayCache::default();
        let applied = apply_signed_update(&state, &signed, CHAOS_NOW_UNIX, &mut cache)
            .expect("a fully valid membership update must be accepted");
        assert_eq!(
            applied.epoch,
            state.epoch + 1,
            "a valid update must advance the epoch by exactly one"
        );
    }

    #[test]
    fn funnel_case_ids_match_the_fixture_corpus_exactly() {
        let cases = funnel_cases("all").expect("cases should build");
        let case_ids: BTreeSet<&str> = cases.iter().map(|case| case.id).collect();
        let corpus_ids: BTreeSet<&str> = live_signed_state_chaos::scenario_names()
            .into_iter()
            .collect();
        assert_eq!(case_ids, corpus_ids);
        // Every case maps to a configured stage, so no report stage is empty.
        let stage_names: BTreeSet<&str> = signed_state_stages()
            .iter()
            .map(|stage| stage.name)
            .collect();
        for case in &cases {
            assert!(
                stage_names.contains(case.stage_name),
                "case {} maps to unknown stage {}",
                case.id,
                case.stage_name
            );
        }
        for stage in signed_state_stages() {
            assert!(
                cases.iter().any(|case| case.stage_name == stage.name),
                "configured stage {} has no verifier case",
                stage.name
            );
        }
    }

    #[test]
    fn funnel_cases_reject_unknown_scenario_names() {
        let err = match funnel_cases("not-real") {
            Err(err) => err,
            Ok(_) => panic!("unknown scenario must reject"),
        };
        assert!(err.contains("unsupported scenario"), "{err}");
    }

    #[test]
    fn report_marks_all_stages_pass_when_every_case_is_rejected() {
        let config = parse(&["--dry-run"]).expect("config should parse");
        let output_dir = test_dir("all-scenarios");
        let manifest = generate_manifest(&output_dir, "all", 123).expect("manifest");
        let scenarios = validate_manifest(&manifest).expect("validate");
        let outcomes: Vec<CaseOutcome> = funnel_cases("all")
            .expect("cases")
            .iter()
            .map(evaluate)
            .collect();
        let all_passed = outcomes.iter().all(|outcome| outcome.passed);
        let report = render_report(
            &config,
            Path::new("/tmp/manifest.json"),
            &scenarios,
            &outcomes,
            all_passed,
        );
        assert_eq!(report["overall_status"], "pass");
        assert_eq!(report["verifier_case_count"], 6);
        let stages = report["stages"].as_array().expect("stages");
        assert_eq!(stages.len(), 5);
        assert!(stages.iter().all(|stage| stage["status"] == "pass"));
        let _ = fs::remove_dir_all(output_dir);
    }

    #[test]
    fn report_fails_when_a_stage_has_no_verifier_case() {
        let config = parse(&["--dry-run"]).expect("config should parse");
        let outcomes: Vec<CaseOutcome> = funnel_cases("forged_signature_attempt")
            .expect("cases")
            .iter()
            .map(evaluate)
            .collect();
        let report = render_report(
            &config,
            Path::new("/tmp/manifest.json"),
            &[],
            &outcomes,
            false,
        );
        assert_eq!(report["overall_status"], "fail");
        let stages = report["stages"].as_array().expect("stages");
        let replay = stages
            .iter()
            .find(|stage| stage["name"] == "chaos_replay_old_membership")
            .expect("replay stage present");
        assert_eq!(replay["status"], "fail");
    }

    #[test]
    fn every_configured_stage_has_an_offline_fixture_in_all_scenarios() {
        let output_dir = test_dir("stage-coverage");
        let manifest = generate_manifest(&output_dir, "all", 123).expect("manifest");
        let scenarios = validate_manifest(&manifest).expect("validate");
        let present = scenarios
            .iter()
            .map(|scenario| scenario.stage_name.as_str())
            .collect::<BTreeSet<_>>();
        for stage in signed_state_stages() {
            assert!(
                present.contains(stage.name),
                "missing fixture for {}",
                stage.name
            );
        }
        let _ = fs::remove_dir_all(output_dir);
    }
}
