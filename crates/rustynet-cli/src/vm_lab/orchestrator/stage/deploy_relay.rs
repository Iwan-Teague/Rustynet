#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::role_validation::relay::relay_lab_runtime_implemented;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

/// File name (under `ctx.report_dir`) the reported-skip note is written to
/// when a Relay node's platform has no relay-runtime-deploy adapter yet
/// (Windows, pending its SCM relay install).
const REPORTED_SKIPS_FILENAME: &str = "relay_deploy.reported_skips.json";

/// Deploy the `rustynet-relay` sibling service onto every Relay-role node so
/// the downstream [`RelayValidationStage`](super::relay_validation) has a live
/// relay to prove — closing the gap where the standard orchestrator advertised
/// the `relay_host` capability in signed membership but never actually
/// installed the relay runtime (so `relay_validation` could only ever
/// fail-closed with "relay role not deployed?").
///
/// # Why a dedicated stage (not folded into bootstrap or enforce)
///
/// The relay datapath/health is served by a **separate** `rustynet-relay`
/// binary + per-OS service unit, not by `rustynetd`. Deploying it has two
/// halves with opposite network requirements:
///
///   * The **binary build** (`cargo build -p rustynet-relay --features daemon`)
///     needs the cargo registry, so it co-locates with the daemon build in the
///     bootstrap script while the network is still open
///     (`auto_tunnel_enforce=false`). The bootstrap installs it to
///     `/usr/local/bin/rustynet-relay` on every node, so a node assigned (or
///     later role-switched to) Relay always has the binary available.
///   * The **service install** (this stage) needs no network: it places the
///     relay verifier key and enables the unit. It therefore runs *after*
///     `enforce_baseline_runtime` engages the killswitch — placement that would
///     break a cargo build but is fine for a key-copy + `systemctl enable`.
///
/// This split mirrors the proven bash orchestrator's relay-deploy sequence.
///
/// # What it does per Linux Relay node
///
///   1. Derives the relay `--verifier-key` (raw 32 bytes) from the assignment
///      authority public key the orchestrator already distributed to the node
///      as `/etc/rustynet/assignment.pub` (hex). That is a PUBLIC verifier key,
///      never secret; reusing it avoids minting/distributing new trust material.
///   2. Installs it at the unit's fail-closed-checked path
///      (`/etc/rustynet/relay-verifier.pub`, mode 0644).
///   3. Installs + enables + starts `rustynet-relay.service` via the shared
///      `ops install-systemd-relay` helper (the one hardened relay-install
///      path, also used by the role-transition orchestrator).
///
/// # Cross-OS posture
///
/// Relay runtime deploy is live-wired on Linux today. macOS and Windows Relay
/// nodes are **reported-skipped** (named in `relay_deploy.reported_skips.json`,
/// never a silent pass) until a green standard-orchestrator run is archived and
/// [`NodeRole::is_supported_for_platform`] is promoted for them (cross-OS Phase
/// 8). The same posture flag gates [`RelayValidationStage`], so a flag flip
/// lights up both deploy and validation together.
///
/// Runs after `validate_baseline_runtime` (daemon up + posture validated) and
/// before `relay_validation`. A run with no Relay nodes is a skip-noop.
pub struct DeployRelayServiceStage;

impl OrchestrationStage for DeployRelayServiceStage {
    fn id(&self) -> StageId {
        StageId::DeployRelayService
    }
    fn name(&self) -> &str {
        "deploy_relay_service"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::ValidateBaselineRuntime]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[NodeRole::Relay]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::PerNode
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        // Self-filter for Relay nodes (the runner ignores applies_to_roles).
        let relay_aliases: Vec<String> = ctx
            .assignments
            .iter()
            .filter(|a| a.role == NodeRole::Relay)
            .map(|a| a.alias.clone())
            .collect();

        // No Relay nodes in this lab → nothing to deploy. Skip-noop, mirroring
        // relay_validation's empty-assignment case.
        if relay_aliases.is_empty() {
            return StageOutcome::Passed;
        }

        let mut failures: Vec<String> = Vec::new();
        // (alias, platform) pairs that were reported-skipped because relay
        // runtime deploy is not yet live-supported on their platform.
        let mut reported_skips: Vec<(String, String)> = Vec::new();

        for alias in &relay_aliases {
            let adapter = match ctx.adapters.get(alias.as_str()) {
                Some(adapter) => adapter,
                None => {
                    // An assigned Relay node with no adapter is a construction
                    // bug, never "nothing to deploy" — fail closed.
                    failures.push(format!("{alias}: no adapter for relay node"));
                    continue;
                }
            };
            let platform = adapter.platform();

            // Runtime-implemented gate (single source of truth, shared with
            // relay_validation): deploy the relay only where an adapter can.
            // Linux + macOS deploy live; a platform with no relay-deploy adapter
            // (Windows today) is reported-skipped — named, never a silent pass.
            // This is decoupled from is_supported_for_platform on purpose: the
            // live deploy + validation here is what *produces* the green
            // evidence that later promotes is_supported_for_platform.
            if !relay_lab_runtime_implemented(platform) {
                reported_skips.push((alias.clone(), format!("{platform:?}")));
                continue;
            }

            if let Err(e) = adapter.deploy_relay_service() {
                failures.push(format!("{alias}: {e}"));
            }
        }

        // Record the reported skips as evidence (best-effort write); these are
        // not failures, but they MUST be named on disk so a macOS/Windows relay
        // node is never silently treated as deployed.
        if !reported_skips.is_empty() {
            write_reported_skips_note(ctx, &reported_skips);
        }

        outcome_for(&failures, &reported_skips)
    }
}

/// Decide the stage outcome from the per-node tally — a pure function so the
/// skip-vs-pass-vs-fail decision is unit-testable without constructing a
/// per-OS adapter (whose `platform()` would otherwise have to be Windows for
/// the reported-skip case).
///
/// Honest cross-OS posture (Wave 1):
///   * any hard failure ⇒ `Failed` (a deploy/construction error trumps a skip);
///   * else any reported-skip — a relay node on a platform with no relay-deploy
///     adapter (Windows today) — ⇒ `Skipped`, so the run goes
///     `RunStatus::Partial` instead of falsely green. The skipped
///     `(alias, platform)` pairs are named in the side-car note written above;
///   * else (no failures, no reported-skips — a genuine all-Linux deploy; the
///     empty-relay-lab no-op is handled before this is called) ⇒ `Passed`.
fn outcome_for(failures: &[String], reported_skips: &[(String, String)]) -> StageOutcome {
    if !failures.is_empty() {
        StageOutcome::Failed(failures.join("; "))
    } else if !reported_skips.is_empty() {
        StageOutcome::Skipped
    } else {
        StageOutcome::Passed
    }
}

/// Serialize the reported-skip note as pretty JSON bytes. Pure (no I/O) so a
/// unit test can assert the content without touching the filesystem.
fn reported_skips_json_bytes(reported_skips: &[(String, String)]) -> Vec<u8> {
    let skipped: Vec<serde_json::Value> = reported_skips
        .iter()
        .map(|(alias, platform)| serde_json::json!({ "alias": alias, "platform": platform }))
        .collect();
    let body = serde_json::json!({
        "stage": "deploy_relay_service",
        "reported_skipped_relay_deploy": skipped,
        "reason": "relay runtime deploy is implemented for Linux + macOS; a relay node on a \
                   platform with no relay-deploy adapter (Windows, pending its SCM relay \
                   install) is reported-skipped (named, never a silent pass) — gated on \
                   relay_lab_runtime_implemented, not is_supported_for_platform",
    });
    serde_json::to_vec_pretty(&body).unwrap_or_default()
}

/// Write the reported-skip note to `<report_dir>/relay_deploy.reported_skips.json`.
/// Best-effort: a write failure does not fail the stage (the deploy work that
/// did run already succeeded), but the common path leaves a machine-readable
/// artifact naming every skipped relay node.
fn write_reported_skips_note(ctx: &OrchestrationContext, reported_skips: &[(String, String)]) {
    let path = ctx.report_dir.join(REPORTED_SKIPS_FILENAME);
    let _ = std::fs::write(&path, reported_skips_json_bytes(reported_skips));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
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
        }
    }

    #[test]
    fn stage_identity_and_dependencies() {
        let stage = DeployRelayServiceStage;
        assert_eq!(stage.id(), StageId::DeployRelayService);
        assert_eq!(stage.name(), "deploy_relay_service");
        assert_eq!(stage.id().as_str(), "deploy_relay_service");
        assert_eq!(stage.dependencies(), &[StageId::ValidateBaselineRuntime]);
        assert!(matches!(stage.fanout(), StageFanout::PerNode));
        assert_eq!(stage.applies_to_roles(), &[NodeRole::Relay]);
    }

    #[test]
    fn empty_assignments_passes_skip_noop() {
        let mut ctx = empty_ctx();
        assert_eq!(
            DeployRelayServiceStage.execute(&mut ctx),
            StageOutcome::Passed
        );
    }

    #[test]
    fn no_relay_role_among_non_relay_assignments_passes_skip_noop() {
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
            DeployRelayServiceStage.execute(&mut ctx),
            StageOutcome::Passed
        );
    }

    #[test]
    fn relay_role_without_adapter_fails_closed() {
        // A Relay assignment with no adapter wired must fail closed (never
        // silently skip an undeployable relay).
        let mut ctx = empty_ctx();
        ctx.assignments = vec![NodeRoleAssignment {
            alias: "relay-1".to_owned(),
            role: NodeRole::Relay,
        }];
        match DeployRelayServiceStage.execute(&mut ctx) {
            StageOutcome::Failed(msg) => {
                assert!(msg.contains("relay-1"), "got: {msg}");
                assert!(msg.contains("no adapter"), "got: {msg}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn outcome_for_reported_skip_with_no_failures_is_skipped() {
        // A relay node on a platform with no relay-deploy adapter (Windows) is
        // reported-skipped with no hard failure ⇒ stage Skipped, which
        // build_live_lab_run_report maps to RunStatus::Partial (honest: this
        // stage did not fully prove every relay node, so the run is not green).
        let reported_skips = vec![("relay-win".to_owned(), "Windows".to_owned())];
        assert_eq!(
            outcome_for(&[], &reported_skips),
            StageOutcome::Skipped,
            "reported-skip + no failures must be Skipped, not Passed"
        );
    }

    #[test]
    fn outcome_for_no_failures_no_skips_is_passed() {
        // A genuine all-Linux deploy (nothing skipped, nothing failed) stays
        // Passed — the empty-relay-lab no-op also lands here.
        assert_eq!(outcome_for(&[], &[]), StageOutcome::Passed);
    }

    #[test]
    fn outcome_for_failure_is_failed_even_with_skips() {
        // A hard failure trumps a reported-skip: the stage is Failed.
        let failures = vec!["relay-1: boom".to_owned()];
        let reported_skips = vec![("relay-win".to_owned(), "Windows".to_owned())];
        match outcome_for(&failures, &reported_skips) {
            StageOutcome::Failed(msg) => assert!(msg.contains("relay-1: boom"), "got: {msg}"),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn reported_skips_note_names_every_skipped_relay() {
        // The note must name each skipped (alias, platform) pair so a
        // macOS/Windows relay is never silently treated as deployed.
        let skips = vec![
            ("relay-mac".to_owned(), "Macos".to_owned()),
            ("relay-win".to_owned(), "Windows".to_owned()),
        ];
        let bytes = reported_skips_json_bytes(&skips);
        let parsed: serde_json::Value =
            serde_json::from_slice(&bytes).expect("reported-skip note must be valid JSON");
        assert_eq!(parsed["stage"], "deploy_relay_service");
        let listed = parsed["reported_skipped_relay_deploy"]
            .as_array()
            .expect("skip list");
        assert_eq!(listed.len(), 2);
        assert!(
            listed
                .iter()
                .any(|v| v["alias"] == "relay-mac" && v["platform"] == "Macos")
        );
        assert!(
            listed
                .iter()
                .any(|v| v["alias"] == "relay-win" && v["platform"] == "Windows")
        );
    }
}
