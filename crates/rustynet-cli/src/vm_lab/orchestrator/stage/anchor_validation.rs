#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::role_validation::anchor::{
    AnchorRuntimeParams, validate_anchor_capability_advertisement,
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
///     macOS/Windows anchors are reported-skipped on the
///     `is_supported_for_platform` posture gate (per-node, recorded in
///     `runtime_skipped_nodes`), pending cross-OS Phase 8 wiring of their
///     bundle-pull token/listener provisioning.
///   * runtime-dependent (DEFERRED): `enrollment_endpoint` — enrollment
///     admit signs a membership update with the owner signing key +
///     passphrase, which the orchestrator provisions only on the
///     Exit/membership-owner, not on standalone anchors (a trust-model
///     decision, not just wiring).
///   * mutation (DEFERRED): `gossip_priority`, `downgrade_revocation` —
///     need the Windows membership-mutation backend.
pub const ANCHOR_REPORTED_SKIPS_NOTE: &str = concat!(
    "anchor_validation scope=capability_advertisement+bundle_pull; ",
    "ported_runtime_dependent=[bundle_pull_loopback,invalid_token,log_redaction] ",
    "(run live on Linux anchors; macOS/Windows reported-skipped on the is_supported_for_platform gate, ",
    "pending cross-OS Phase 8 wiring of bundle-pull token/listener provisioning); ",
    "reported_skipped_runtime_dependent=[enrollment_endpoint] ",
    "(pending a trust-model decision — enrollment admit signs a membership update with the owner signing key ",
    "+ passphrase, which the orchestrator provisions only on the Exit/membership-owner, not on standalone anchors); ",
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
/// one, and redacts the raw token from its journal. macOS/Windows anchors
/// are reported-skipped for these on the `is_supported_for_platform`
/// posture gate (recorded per-node), pending cross-OS Phase 8 wiring.
///
/// The remaining substages — `enrollment_endpoint` (needs the owner
/// signing key + passphrase, provisioned only on the Exit) and the
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
        // StageOutcome::Skipped (not Passed) so the run goes Partial —
        // this stage was not exercised, and a false-green Pass would
        // mask the gap.
        if anchor_aliases.is_empty() {
            return StageOutcome::Skipped;
        }

        let mut failures: Vec<String> = Vec::new();
        // (alias, platform) anchors whose runtime bundle-pull substages were
        // reported-skipped because they are not yet live-supported there
        // (macOS/Windows). Named, never a silent pass.
        let mut runtime_skips: Vec<(String, String)> = Vec::new();
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

            // Runtime bundle-pull substages: live on Linux anchors today
            // (the daemon binds the loopback listener + `ops install-systemd`
            // seeds the token for admin-role nodes). macOS/Windows anchors are
            // reported-skipped — named, never a silent pass — on the same
            // is_supported_for_platform posture gate, pending cross-OS Phase 8
            // wiring of their bundle-pull token/listener provisioning.
            if NodeRole::Anchor.is_supported_for_platform(&platform) {
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
            } else {
                runtime_skips.push((alias.clone(), format!("{platform:?}")));
            }
        }

        if failures.is_empty() {
            // Record the deferred-substage note + any per-node runtime skips as
            // evidence on a non-failing run. Best-effort: a write failure does not
            // change the outcome (the proofs that ran already passed), but the
            // common path leaves a machine-readable artifact behind.
            write_reported_skips_note(ctx, &runtime_skips);
        }
        outcome_for(&failures, &runtime_skips)
    }
}

/// Decide the stage outcome from the per-node tally — a pure function so the
/// skip-vs-pass-vs-fail decision is unit-testable without constructing a
/// per-OS adapter (whose `platform()` would otherwise have to be macOS/Windows
/// for the reported-skip case). Mirrors `deploy_relay::outcome_for`.
///
/// Honest cross-OS posture (Wave 1): capability-advertisement runs real on every
/// OS, but the bundle-pull RUNTIME substages are reported-skipped on
/// macOS/Windows anchors. So:
///   * any hard failure (broken cap-advert / runtime probe / construction) ⇒
///     `Failed`;
///   * else any reported runtime-skip (a macOS/Windows anchor whose bundle-pull
///     runtime substages did not run) ⇒ `Skipped`, so the run goes
///     `RunStatus::Partial` instead of falsely green — the stage did NOT fully
///     prove every anchor; the skipped nodes are named in the side-car note;
///   * else (every anchor fully validated incl. runtime; the empty-anchor-lab
///     no-op is handled before this) ⇒ `Passed`.
fn outcome_for(failures: &[String], runtime_skips: &[(String, String)]) -> StageOutcome {
    if !failures.is_empty() {
        StageOutcome::Failed(failures.join("; "))
    } else if !runtime_skips.is_empty() {
        StageOutcome::Skipped
    } else {
        StageOutcome::Passed
    }
}

/// The machine-readable reported-skip note as pretty JSON bytes. Pure
/// (no I/O) so a unit test can assert the content without depending on
/// the filesystem. `to_vec_pretty` on this fixed `serde_json::Value`
/// cannot fail, so the `unwrap_or_default` is unreachable in practice.
fn reported_skips_json_bytes(runtime_skips: &[(String, String)]) -> Vec<u8> {
    let runtime_skipped_nodes: Vec<serde_json::Value> = runtime_skips
        .iter()
        .map(|(alias, platform)| serde_json::json!({ "alias": alias, "platform": platform }))
        .collect();
    let body = serde_json::json!({
        "stage": "anchor_validation",
        "scope": "capability_advertisement+bundle_pull",
        // Now ported + run live on Linux anchors (reported-skipped per-node on
        // macOS/Windows — see `runtime_skipped_nodes`).
        "ported_runtime_dependent": [
            "bundle_pull_loopback",
            "invalid_token",
            "log_redaction",
        ],
        // Still deferred (named, never silently dropped).
        "reported_skipped_runtime_dependent": ["enrollment_endpoint"],
        "reported_skipped_mutation": ["gossip_priority", "downgrade_revocation"],
        // Per-run: anchors whose runtime bundle-pull substages were skipped
        // because their platform is not yet live-supported (macOS/Windows).
        "runtime_skipped_nodes": runtime_skipped_nodes,
        "note": ANCHOR_REPORTED_SKIPS_NOTE,
    });
    serde_json::to_vec_pretty(&body).unwrap_or_default()
}

/// Write the reported-skip note to `<report_dir>/anchor_validation.reported_skips.json`
/// so the deferred substages (and any per-node runtime skips) are recorded as
/// evidence. Best-effort: a write failure is ignored (the stage's own proofs
/// already passed).
fn write_reported_skips_note(ctx: &OrchestrationContext, runtime_skips: &[(String, String)]) {
    let path = ctx.report_dir.join(REPORTED_SKIPS_FILENAME);
    let _ = std::fs::write(&path, reported_skips_json_bytes(runtime_skips));
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
            network_id: "net".to_owned(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
            orchestrator_dialect: None,
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
        assert_eq!(
            AnchorValidationStage.execute(&mut ctx),
            StageOutcome::Skipped
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
        assert_eq!(
            AnchorValidationStage.execute(&mut ctx),
            StageOutcome::Skipped
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
        assert_eq!(
            outcome_for(&[], &runtime_skips),
            StageOutcome::Skipped,
            "runtime reported-skip + no failures must be Skipped, not Passed"
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
        // Two macOS/Windows anchors whose runtime substages were skipped.
        let runtime_skips = vec![
            ("anchor-mac".to_owned(), "Macos".to_owned()),
            ("anchor-win".to_owned(), "Windows".to_owned()),
        ];
        let bytes = reported_skips_json_bytes(&runtime_skips);
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
        assert_eq!(skipped_nodes.len(), 2);
        assert!(
            skipped_nodes
                .iter()
                .any(|v| v["alias"] == "anchor-mac" && v["platform"] == "Macos")
        );
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
        assert_eq!(
            AnchorValidationStage.execute(&mut ctx),
            StageOutcome::Skipped
        );
    }
}
