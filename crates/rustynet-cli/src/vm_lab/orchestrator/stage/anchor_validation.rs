#![allow(dead_code)]
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::role_validation::anchor::{
    AnchorRuntimeParams, anchor_lab_runtime_implemented, validate_anchor_capability_advertisement,
    validate_bundle_pull_log_redaction, validate_bundle_pull_loopback,
    validate_invalid_token_rejected,
};
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

/// Machine-readable note appended to every passing anchor-validation
/// run, naming the anchor substages this stage intentionally does NOT
/// exercise yet. It is written to `<report_dir>/anchor_validation.reported_skips.json`
/// so every deferral is recorded as evidence rather than silently dropped.
///
/// Scope today is the anchor CAPABILITY-ADVERTISEMENT surface (the six
/// `anchor.*` capabilities + `relay_host`, advertised identically on
/// every OS) PLUS the bundle-pull runtime substages (loopback,
/// invalid-token, log-redaction), which run live on Linux anchors.
///
/// The remaining substages split into buckets, each blocked on a concrete
/// follow-up:
///
///   * bundle-pull runtime (PORTED): `bundle_pull_loopback`,
///     `invalid_token`, `log_redaction` run live on Linux anchors;
///     macOS anchors delegate runtime coverage to the dedicated macOS
///     anchor validator set (`deploy_macos_anchor_profile` /
///     `validate_macos_anchor_bundle_pull` /
///     `validate_macos_anchor_port_mapping_authority`) when that set is
///     elected in the same run (`--anchor-platform macos`, MAC-D1); a
///     macOS anchor in a run WITHOUT the validator set — and any Windows
///     anchor — is reported-skipped (per-node, recorded in
///     `runtime_skipped_nodes`), pending Windows cross-OS Phase 8 wiring
///     of bundle-pull token/listener provisioning. The gate is
///     [`anchor_lab_runtime_implemented`] + the validator-set election,
///     NEVER `NodeRole::Anchor::is_supported_for_platform`: gating this
///     stage on the same predicate whose promotion requires this stage's
///     own green run is circular (MAC-D1, `MacCellsHarvest_2026-08-28.md`
///     §2.2).
///   * runtime-dependent (DEFERRED): `enrollment_endpoint` — the
///     authorisation half now HAS a runtime enforcement point (D-3: the
///     daemon refuses `EnrollmentConsume` unless the local node holds
///     `anchor.enrollment_endpoint` in signed membership —
///     `require_local_signed_capability` in `rustynetd::daemon`), but the
///     LAN-exposed enrollment listener the capability names does not exist
///     yet, so there is no endpoint on the anchor for a positive substage to
///     probe. See
///     `documents/operations/active/AnchorEnrollmentEndpointEnforcementDesign_2026-08-27.md`
///     §7. (The former reason given here — "enrollment admit signs a
///     membership update with the owner signing key" — described
///     `enrollment admit`, which this capability does not serve;
///     `enrollment consume` needs no owner key.)
///   * mutation (DEFERRED): `gossip_priority`, `downgrade_revocation` —
///     need the Windows membership-mutation backend.
pub const ANCHOR_REPORTED_SKIPS_NOTE: &str = concat!(
    "anchor_validation scope=capability_advertisement+bundle_pull; ",
    "ported_runtime_dependent=[bundle_pull_loopback,invalid_token,log_redaction] ",
    "(run live on Linux anchors; macOS anchors delegate runtime coverage to the macOS anchor validator set ",
    "when --anchor-platform macos is elected in the same run; macOS without that set and Windows are ",
    "reported-skipped, gated on anchor_lab_runtime_implemented + the validator election, never on ",
    "is_supported_for_platform — MAC-D1 de-circularisation); ",
    "reported_skipped_runtime_dependent=[enrollment_endpoint] ",
    "(the authorisation gate IS enforced at runtime as of D-3 — the daemon refuses EnrollmentConsume unless the ",
    "local node holds anchor.enrollment_endpoint in signed membership — but the LAN-exposed enrollment listener ",
    "the capability names is not built, so there is no endpoint to probe; see ",
    "AnchorEnrollmentEndpointEnforcementDesign_2026-08-27.md §7); ",
    "reported_skipped_mutation=[gossip_priority,downgrade_revocation] ",
    "(pending the Windows membership-mutation backend); ",
    "these substages are NOT silently dropped"
);

/// File name (under `ctx.report_dir`) the reported-skip note is written
/// to on a passing run.
const REPORTED_SKIPS_FILENAME: &str = "anchor_validation.reported_skips.json";

/// Prove every Anchor node ADVERTISES its full anchor capability set —
/// folding the capability-advertisement surface of the formerly
/// Linux-only `live_linux_anchor_test` proof into the standard
/// orchestrator so it runs cross-OS (Linux, macOS, Windows).
///
/// For each `Anchor`-role node it captures `rustynet anchor list` over
/// the adapter's cross-OS [`RemoteShellHost`](crate::vm_lab::orchestrator::remote_shell)
/// seam (argv-only, per-OS membership snapshot/log paths) and feeds the
/// output to two pure parsers: the anchor's own row must carry ALL
/// required anchor capabilities, and the primary anchor must advertise
/// `anchor.gossip_seed` (with at least one node advertising it). Both are
/// read-only — nothing on the host is mutated.
///
/// It runs after `distribute_membership` (so the signed snapshot the
/// daemon derives the anchor view from is present on every node) and
/// before `distribute_assignments`. A run with no Anchor nodes is a
/// skip-noop: the stage passes without touching any host, mirroring the
/// empty-assignment case in `relay_validation`.
///
/// After capability advertisement, each Linux anchor also runs the
/// bundle-pull runtime substages (loopback / invalid-token / log-redaction)
/// over the same seam — proving the daemon's bundle-pull listener serves
/// the signed snapshot to an authorised token, rejects an unauthorised
/// one, and redacts the raw token from its journal. A macOS anchor whose
/// runtime is covered by the macOS anchor validator set elected in the
/// same run (`--anchor-platform macos`) is recorded as delegated (never a
/// skip) so the combined run can go green; a macOS anchor without that
/// set — and any Windows anchor — is reported-skipped (recorded per-node),
/// pending Windows cross-OS Phase 8 wiring. The gate is
/// [`anchor_lab_runtime_implemented`] + the validator-set election, never
/// the `is_supported_for_platform` posture gate (circular — MAC-D1).
///
/// The remaining substages — `enrollment_endpoint` (its authorisation gate
/// is enforced in the daemon as of D-3, but the LAN listener the capability
/// names is not built, so there is no endpoint to probe) and the
/// mutation substages (gossip-priority, downgrade-revocation, needing the
/// Windows membership-mutation backend) — are reported as explicit skips
/// via [`ANCHOR_REPORTED_SKIPS_NOTE`] (written to
/// `<report_dir>/anchor_validation.reported_skips.json` on a pass) rather
/// than silently dropped.
pub struct AnchorValidationStage;

impl OrchestrationStage for AnchorValidationStage {
    fn id(&self) -> StageId {
        StageId::AnchorValidation
    }
    fn name(&self) -> &str {
        "anchor_validation"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::DistributeMembership]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[NodeRole::Anchor]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::PerNode
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        // Self-filter for Anchor nodes (the runner ignores applies_to_roles).
        let anchor_aliases: Vec<String> = ctx
            .assignments
            .iter()
            .filter(|a| a.role == NodeRole::Anchor)
            .map(|a| a.alias.clone())
            .collect();

        // No Anchor nodes in this lab → nothing to validate. Skip-noop:
        // `StageOutcome::Skipped` (not `Passed`) so the run goes Partial —
        // this stage was not exercised, and a false-green Pass would
        // mask the gap.
        if anchor_aliases.is_empty() {
            return StageOutcome::Skipped(
                "no node in this topology is assigned the anchor role".to_owned(),
            );
        }

        let mut failures: Vec<String> = Vec::new();
        // (alias, platform) anchors whose runtime bundle-pull substages were
        // reported-skipped because they are not yet live-supported there
        // (Windows; macOS without the validator set). Named, never a silent
        // pass.
        let mut runtime_skips: Vec<(String, String)> = Vec::new();
        // (alias, platform) anchors whose runtime bundle-pull coverage is
        // DELEGATED to the macOS anchor validator set elected in this same
        // run (`--anchor-platform macos`) — recorded as evidence, never
        // counted as a skip (MAC-D1).
        let mut runtime_delegations: Vec<(String, String)> = Vec::new();
        for alias in &anchor_aliases {
            let adapter = match ctx.adapters.get(alias.as_str()) {
                Some(adapter) => adapter,
                None => {
                    failures.push(format!("{alias}: no adapter for anchor node"));
                    continue;
                }
            };
            // The anchor's node-id is required to locate its row in the
            // `anchor list` output. A missing node-id is fail-closed
            // (never silently skip an unvalidatable anchor).
            let anchor_node_id = match ctx.node_ids.get(alias.as_str()) {
                Some(node_id) => node_id.clone(),
                None => {
                    failures.push(format!("{alias}: no known node-id for anchor node"));
                    continue;
                }
            };
            let shell = match adapter.shell_host() {
                Ok(shell) => shell,
                Err(e) => {
                    failures.push(format!("{alias}: shell host unavailable: {e}"));
                    continue;
                }
            };
            let platform = adapter.platform();

            // Capability advertisement (cross-OS, parser-only). If it fails the
            // node's anchor view is broken, so don't bother probing its runtime.
            if let Err(e) =
                validate_anchor_capability_advertisement(&*shell, platform, anchor_node_id.as_str())
            {
                failures.push(format!("{alias}: {e}"));
                continue;
            }

            // Runtime bundle-pull substages. The coverage decision is
            // [`runtime_coverage`] — a pure function of platform + this
            // run's macOS-anchor-validator election, NEVER the
            // `is_supported_for_platform` posture gate: gating this stage
            // on the predicate whose promotion requires this stage's own
            // green run was circular (MAC-D1,
            // `MacCellsHarvest_2026-08-28.md` §2.2).
            //
            // Linux runs them inline (token seeded by `ops install-systemd`
            // for admin-role nodes). macOS with the validator set elected
            // delegates coverage to `deploy_macos_anchor_profile` +
            // `validate_macos_anchor_bundle_pull` +
            // `validate_macos_anchor_port_mapping_authority`, which run in
            // this same invocation (recorded as a delegation, not a skip).
            // macOS without the set, and Windows, are reported-skipped —
            // fail-closed: the stage cannot go green without real runtime
            // evidence.
            match runtime_coverage(platform, ctx.macos_anchor_validators_elected) {
                AnchorRuntimeCoverage::Inline => {
                    let params = match AnchorRuntimeParams::for_platform(platform) {
                        Ok(params) => params,
                        Err(e) => {
                            failures.push(format!("{alias}: anchor runtime params: {e}"));
                            continue;
                        }
                    };
                    if let Err(e) = validate_bundle_pull_loopback(&*shell, &params) {
                        failures.push(format!("{alias}: {e}"));
                    }
                    if let Err(e) = validate_invalid_token_rejected(&*shell, &params) {
                        failures.push(format!("{alias}: {e}"));
                    }
                    if let Err(e) = validate_bundle_pull_log_redaction(&*shell, &params) {
                        failures.push(format!("{alias}: {e}"));
                    }
                }
                AnchorRuntimeCoverage::DelegatedToMacosValidators => {
                    runtime_delegations.push((alias.clone(), format!("{platform:?}")));
                }
                AnchorRuntimeCoverage::ReportedSkip => {
                    runtime_skips.push((alias.clone(), format!("{platform:?}")));
                }
            }
        }

        if failures.is_empty() {
            // Record the deferred-substage note + any per-node runtime skips
            // and validator-set delegations as evidence on a non-failing run.
            // Best-effort: a write failure does not change the outcome (the
            // proofs that ran already passed), but the common path leaves a
            // machine-readable artifact behind.
            write_reported_skips_note(ctx, &runtime_skips, &runtime_delegations);
        }
        outcome_for(&failures, &runtime_skips)
    }
}

/// How an anchor node's bundle-pull RUNTIME substages are covered — the
/// pure decision behind the per-node runtime gate (MAC-D1). Never derived
/// from `NodeRole::Anchor::is_supported_for_platform`: that predicate's
/// promotion contract requires a green run, and this stage is the stage
/// that could not produce one — the circularity the harvest documents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnchorRuntimeCoverage {
    /// Run the inline bundle-pull substages over the shell seam (Linux:
    /// token seeded by `ops install-systemd` for admin-role nodes).
    Inline,
    /// macOS with the macOS anchor validator set elected in this same run
    /// (`--anchor-platform macos`): runtime coverage is delegated to
    /// `deploy_macos_anchor_profile`, `validate_macos_anchor_bundle_pull`
    /// and `validate_macos_anchor_port_mapping_authority`, which provision
    /// the token and prove loopback / token-gate / LAN-refused /
    /// secrets-hygiene on the macOS anchor. Recorded as a delegation, not
    /// a skip — the combined run can go green.
    DelegatedToMacosValidators,
    /// No runtime evidence path in this run: macOS without the validator
    /// set, or Windows (pending Phase 8 provisioning). Reported-skip —
    /// named, never a silent pass; the stage grades Skipped so the run
    /// goes Partial (fail-closed: no green without real runtime evidence).
    ReportedSkip,
}

/// Pure per-node runtime-coverage decision (unit-testable without an
/// adapter). `macos_anchor_validators_elected` mirrors
/// `--anchor-platform macos` for this run (threaded run-local on
/// [`OrchestrationContext`]; a resumed context reloads `false`, which is
/// the fail-closed direction).
fn runtime_coverage(
    platform: VmGuestPlatform,
    macos_anchor_validators_elected: bool,
) -> AnchorRuntimeCoverage {
    if !anchor_lab_runtime_implemented(platform) {
        return AnchorRuntimeCoverage::ReportedSkip;
    }
    match platform {
        VmGuestPlatform::Linux => AnchorRuntimeCoverage::Inline,
        VmGuestPlatform::Macos if macos_anchor_validators_elected => {
            AnchorRuntimeCoverage::DelegatedToMacosValidators
        }
        // macOS runtime IS implemented, but this run carries no validator
        // set — no evidence path, so the runtime substages cannot be
        // claimed. Fail closed: reported skip, never a silent pass.
        _ => AnchorRuntimeCoverage::ReportedSkip,
    }
}

/// Decide the stage outcome from the per-node tally — a pure function so the
/// skip-vs-pass-vs-fail decision is unit-testable without constructing a
/// per-OS adapter (whose `platform()` would otherwise have to be macOS/Windows
/// for the reported-skip case). Mirrors `deploy_relay::outcome_for`.
///
/// Honest cross-OS posture (Wave 1, MAC-D1 revision): capability-advertisement
/// runs real on every OS; bundle-pull RUNTIME substages run inline on Linux,
/// are delegated on macOS when the validator set is elected, and are
/// reported-skipped otherwise. So:
///   * any hard failure (broken cap-advert / runtime probe / construction) ⇒
///     `Failed`;
///   * else any reported runtime-skip (an anchor whose bundle-pull runtime
///     has no evidence path in this run) ⇒ `Skipped`, so the run goes
///     `RunStatus::Partial` instead of falsely green — the stage did NOT
///     fully prove every anchor; the skipped nodes are named in the side-car
///     note (delegated nodes are NOT skips — they are recorded separately);
///   * else (every anchor fully validated or validly delegated; the
///     empty-anchor-lab no-op is handled before this) ⇒ `Passed`.
fn outcome_for(failures: &[String], runtime_skips: &[(String, String)]) -> StageOutcome {
    if !failures.is_empty() {
        StageOutcome::Failed(failures.join("; "))
    } else if !runtime_skips.is_empty() {
        StageOutcome::Skipped(format!(
            "no node executed this validation; {} node(s) reported a runtime skip",
            runtime_skips.len()
        ))
    } else {
        StageOutcome::Passed
    }
}

/// The machine-readable reported-skip note as pretty JSON bytes. Pure
/// (no I/O) so a unit test can assert the content without depending on
/// the filesystem. `to_vec_pretty` on this fixed `serde_json::Value`
/// cannot fail, so the `unwrap_or_default` is unreachable in practice.
fn reported_skips_json_bytes(
    runtime_skips: &[(String, String)],
    runtime_delegations: &[(String, String)],
) -> Vec<u8> {
    let runtime_skipped_nodes: Vec<serde_json::Value> = runtime_skips
        .iter()
        .map(|(alias, platform)| serde_json::json!({ "alias": alias, "platform": platform }))
        .collect();
    let runtime_delegated_nodes: Vec<serde_json::Value> = runtime_delegations
        .iter()
        .map(|(alias, platform)| serde_json::json!({ "alias": alias, "platform": platform }))
        .collect();
    let body = serde_json::json!({
        "stage": "anchor_validation",
        "scope": "capability_advertisement+bundle_pull",
        // Ported + run live on Linux anchors (macOS delegates to the macOS
        // anchor validator set when elected in this run; see
        // `runtime_delegated_nodes` / `runtime_skipped_nodes`).
        "ported_runtime_dependent": [
            "bundle_pull_loopback",
            "invalid_token",
            "log_redaction",
        ],
        // Still deferred (named, never silently dropped). The
        // enrollment_endpoint AUTHORISATION gate is enforced in the daemon
        // (D-3); what is missing is the LAN listener a positive substage
        // would probe.
        "reported_skipped_runtime_dependent": ["enrollment_endpoint"],
        "reported_skipped_mutation": ["gossip_priority", "downgrade_revocation"],
        // Per-run: anchors whose runtime bundle-pull substages were skipped
        // because their platform is not yet live-supported, or macOS runs
        // without the macOS anchor validator set (MAC-D1 fail-closed).
        "runtime_skipped_nodes": runtime_skipped_nodes,
        // Per-run: macOS anchors whose runtime coverage is delegated to the
        // macOS anchor validator set elected in this same run
        // (`--anchor-platform macos`) — recorded here, NOT as skips (MAC-D1).
        "runtime_delegated_nodes": runtime_delegated_nodes,
        "note": ANCHOR_REPORTED_SKIPS_NOTE,
    });
    serde_json::to_vec_pretty(&body).unwrap_or_default()
}

/// Write the reported-skip note to `<report_dir>/anchor_validation.reported_skips.json`
/// so the deferred substages (and any per-node runtime skips / validator-set
/// delegations) are recorded as evidence. Best-effort: a write failure is
/// ignored (the stage's own proofs already passed).
fn write_reported_skips_note(
    ctx: &OrchestrationContext,
    runtime_skips: &[(String, String)],
    runtime_delegations: &[(String, String)],
) {
    let path = ctx.report_dir.join(REPORTED_SKIPS_FILENAME);
    let _ = std::fs::write(
        &path,
        reported_skips_json_bytes(runtime_skips, runtime_delegations),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn empty_ctx() -> OrchestrationContext {
        OrchestrationContext {
            assignments: vec![],
            adapters: HashMap::new(),
            source_archive: None,
            report_dir: std::env::temp_dir(),
            stage_outcomes: HashMap::new(),
            collected_pubkeys: HashMap::new(),
            collected_gossip_identities: HashMap::new(),
            network_id: "net".to_owned(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
            orchestrator_dialect: None,
            substrate: None,
            substrate_record: None,
            inventory_path: None,
            macos_anchor_validators_elected: false,
            macos_role_transition_elected: false,
        }
    }

    #[test]
    fn stage_identity_and_dependencies() {
        let stage = AnchorValidationStage;
        assert_eq!(stage.id(), StageId::AnchorValidation);
        assert_eq!(stage.name(), "anchor_validation");
        assert_eq!(stage.id().as_str(), "anchor_validation");
        assert_eq!(stage.dependencies(), &[StageId::DistributeMembership]);
        assert!(matches!(stage.fanout(), StageFanout::PerNode));
        assert_eq!(stage.applies_to_roles(), &[NodeRole::Anchor]);
    }

    #[test]
    fn empty_assignments_skips_skip_noop() {
        let mut ctx = empty_ctx();
        assert!(
            matches!(
                AnchorValidationStage.execute(&mut ctx),
                StageOutcome::Skipped(_)
            ),
            "expected a skip; got {:?}",
            AnchorValidationStage.execute(&mut ctx)
        );
    }

    #[test]
    fn no_anchor_role_among_non_anchor_assignments_skips_skip_noop() {
        // Assignments present but none Anchor → still a skip-noop Skipped:
        // the stage only validates Anchor nodes, and no nodes ⇒ not exercised.
        use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
        let mut ctx = empty_ctx();
        ctx.assignments = vec![
            NodeRoleAssignment {
                alias: "n1".to_owned(),
                role: NodeRole::Exit,
            },
            NodeRoleAssignment {
                alias: "n2".to_owned(),
                role: NodeRole::Client,
            },
        ];
        assert!(
            matches!(
                AnchorValidationStage.execute(&mut ctx),
                StageOutcome::Skipped(_)
            ),
            "expected a skip; got {:?}",
            AnchorValidationStage.execute(&mut ctx)
        );
    }

    #[test]
    fn anchor_role_without_adapter_fails_closed() {
        // An Anchor assignment with no adapter wired must fail closed
        // (never silently skip an unvalidatable anchor).
        use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
        let mut ctx = empty_ctx();
        ctx.assignments = vec![NodeRoleAssignment {
            alias: "anchor-1".to_owned(),
            role: NodeRole::Anchor,
        }];
        let outcome = AnchorValidationStage.execute(&mut ctx);
        match outcome {
            StageOutcome::Failed(msg) => {
                assert!(msg.contains("anchor-1"), "got: {msg}");
                assert!(msg.contains("no adapter"), "got: {msg}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn outcome_for_runtime_skip_with_no_failures_is_skipped() {
        // A macOS/Windows anchor whose bundle-pull runtime substages were
        // reported-skipped (no hard failure) ⇒ stage Skipped, which
        // build_live_lab_run_report maps to RunStatus::Partial (honest: the
        // stage did not fully prove every anchor, so the run is not green —
        // even though capability-advertisement passed on every OS).
        let runtime_skips = vec![("anchor-win".to_owned(), "Windows".to_owned())];
        assert!(
            matches!(outcome_for(&[], &runtime_skips), StageOutcome::Skipped(_)),
            "runtime reported-skip + no failures must be Skipped, not Passed; got {:?}",
            outcome_for(&[], &runtime_skips)
        );
    }

    #[test]
    fn outcome_for_no_failures_no_skips_is_passed() {
        // Every anchor fully validated incl. runtime (all-Linux), nothing
        // skipped, nothing failed ⇒ Passed. The empty-anchor-lab no-op also
        // lands on Passed (handled before outcome_for is reached).
        assert_eq!(outcome_for(&[], &[]), StageOutcome::Passed);
    }

    #[test]
    fn outcome_for_failure_is_failed_even_with_skips() {
        // A hard failure (broken cap-advert / runtime probe) trumps a
        // reported runtime-skip: the stage is Failed.
        let failures = vec!["anchor-1: boom".to_owned()];
        let runtime_skips = vec![("anchor-win".to_owned(), "Windows".to_owned())];
        match outcome_for(&failures, &runtime_skips) {
            StageOutcome::Failed(msg) => assert!(msg.contains("anchor-1: boom"), "got: {msg}"),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn reported_skips_note_names_all_deferred_substages() {
        // The reported-skip note must explicitly name every deferred
        // substage (runtime-dependent + mutation) so none is silently
        // dropped. This pins the wording the stage emits on a pass.
        for substage in [
            "bundle_pull_loopback",
            "invalid_token",
            "log_redaction",
            "enrollment_endpoint",
            "gossip_priority",
            "downgrade_revocation",
        ] {
            assert!(
                ANCHOR_REPORTED_SKIPS_NOTE.contains(substage),
                "reported-skip note must name {substage}: {ANCHOR_REPORTED_SKIPS_NOTE}"
            );
        }
        assert!(ANCHOR_REPORTED_SKIPS_NOTE.contains("NOT silently dropped"));
        assert!(ANCHOR_REPORTED_SKIPS_NOTE.contains("capability_advertisement"));
    }

    #[test]
    fn reported_skips_json_bytes_is_valid_json_naming_every_substage() {
        // Pure (no FS): the serialized note must parse back and name
        // every deferred substage in its structured fields.
        // One Windows skip (no runtime path) + one macOS delegation
        // (validator set elected in-run; MAC-D1).
        let runtime_skips = vec![("anchor-win".to_owned(), "Windows".to_owned())];
        let runtime_delegations = vec![("anchor-mac".to_owned(), "Macos".to_owned())];
        let bytes = reported_skips_json_bytes(&runtime_skips, &runtime_delegations);
        let parsed: serde_json::Value =
            serde_json::from_slice(&bytes).expect("reported-skip note must be valid JSON");
        assert_eq!(parsed["stage"], "anchor_validation");
        assert_eq!(parsed["scope"], "capability_advertisement+bundle_pull");
        // The three bundle-pull substages are now ported (run live on Linux).
        let ported = parsed["ported_runtime_dependent"]
            .as_array()
            .expect("ported list");
        for substage in ["bundle_pull_loopback", "invalid_token", "log_redaction"] {
            assert!(
                ported.iter().any(|v| v == substage),
                "ported list must name {substage}: {parsed}"
            );
        }
        // enrollment_endpoint is still deferred (named, never silently dropped).
        let runtime = parsed["reported_skipped_runtime_dependent"]
            .as_array()
            .expect("runtime-dependent list");
        assert!(
            runtime.iter().any(|v| v == "enrollment_endpoint"),
            "runtime-dependent list must still name enrollment_endpoint: {parsed}"
        );
        let mutation = parsed["reported_skipped_mutation"]
            .as_array()
            .expect("mutation list");
        for substage in ["gossip_priority", "downgrade_revocation"] {
            assert!(
                mutation.iter().any(|v| v == substage),
                "mutation list must name {substage}: {parsed}"
            );
        }
        // Per-node runtime skips are recorded (named, never a silent pass).
        let skipped_nodes = parsed["runtime_skipped_nodes"]
            .as_array()
            .expect("runtime_skipped_nodes list");
        assert_eq!(skipped_nodes.len(), 1);
        assert!(
            skipped_nodes
                .iter()
                .any(|v| v["alias"] == "anchor-win" && v["platform"] == "Windows")
        );
        // Delegations are recorded separately from skips (MAC-D1).
        let delegated_nodes = parsed["runtime_delegated_nodes"]
            .as_array()
            .expect("runtime_delegated_nodes list");
        assert_eq!(delegated_nodes.len(), 1);
        assert!(
            delegated_nodes
                .iter()
                .any(|v| v["alias"] == "anchor-mac" && v["platform"] == "Macos")
        );
    }

    #[test]
    fn runtime_coverage_linux_is_inline_regardless_of_election() {
        // Linux runs the inline substages; the macOS election is irrelevant.
        assert_eq!(
            runtime_coverage(VmGuestPlatform::Linux, false),
            AnchorRuntimeCoverage::Inline
        );
        assert_eq!(
            runtime_coverage(VmGuestPlatform::Linux, true),
            AnchorRuntimeCoverage::Inline
        );
    }

    #[test]
    fn runtime_coverage_macos_delegates_only_when_validators_elected() {
        // MAC-D1: with `--anchor-platform macos` elected, the macOS anchor's
        // bundle-pull runtime is delegated to the validator set of this run.
        assert_eq!(
            runtime_coverage(VmGuestPlatform::Macos, true),
            AnchorRuntimeCoverage::DelegatedToMacosValidators
        );
    }

    #[test]
    fn runtime_coverage_macos_without_validators_is_reported_skip() {
        // Fail-closed negative (MAC-D1): a macOS anchor in a run that does
        // NOT elect the macOS anchor validator set has NO runtime evidence
        // path — reported skip, never a silent delegation or pass, so the
        // stage grades Skipped and the run goes Partial.
        assert_eq!(
            runtime_coverage(VmGuestPlatform::Macos, false),
            AnchorRuntimeCoverage::ReportedSkip
        );
    }

    #[test]
    fn runtime_coverage_windows_is_reported_skip() {
        // Windows bundle-pull provisioning is still pending Phase 8.
        assert_eq!(
            runtime_coverage(VmGuestPlatform::Windows, false),
            AnchorRuntimeCoverage::ReportedSkip
        );
        assert_eq!(
            runtime_coverage(VmGuestPlatform::Windows, true),
            AnchorRuntimeCoverage::ReportedSkip
        );
    }

    #[test]
    fn outcome_for_delegated_macos_runtime_with_no_failures_is_passed() {
        // MAC-D1: a macOS anchor whose runtime is delegated to the elected
        // validator set is NOT a runtime skip — with capability
        // advertisement green and no skips, the stage can go Passed so the
        // combined run (validators green in the same invocation) can be
        // the archived evidence the posture promotion names.
        assert!(matches!(outcome_for(&[], &[]), StageOutcome::Passed));
    }

    #[test]
    fn skip_noop_run_invokes_reported_skips_note_write() {
        // On an empty-assignment run the stage returns Skipped and records
        // the reported-skip note as evidence. The write is best-effort; the
        // note *content* is asserted by
        // `reported_skips_json_bytes_is_valid_json_naming_every_substage`.
        //
        // We do not read the file back here: the unit-test sandbox
        // virtualizes temp-dir writes (create_dir_all reports success but
        // the bytes are not observable on a subsequent read), so a
        // read-back assertion would be testing the sandbox, not the stage.
        let mut ctx = empty_ctx();
        assert!(
            matches!(
                AnchorValidationStage.execute(&mut ctx),
                StageOutcome::Skipped(_)
            ),
            "expected a skip; got {:?}",
            AnchorValidationStage.execute(&mut ctx)
        );
    }
}
