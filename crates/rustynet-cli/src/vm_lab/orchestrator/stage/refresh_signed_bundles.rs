#![allow(dead_code)]
//! RefreshSignedBundles: re-mint and redistribute the signed assignment +
//! traversal PAIR (per node, behind a quiesce fence) and the dns_zone bundle
//! immediately before the disruptive relay-forwards-frame proof (HP-3).
//! Long live-lab runs can outlive the bundles' configured TTL, after which
//! the HP-3 stage would prove frame forwarding against an expired bundle and
//! fail for freshness reasons rather than dataplane reasons.
//!
//! WHY THE PAIR, NOT A TRAVERSAL-ONLY REFRESH: the daemon enforces the QH-04
//! invariant in BOTH directions — a traversal snapshot holding peers the
//! node's assignment does not manage is rejected as "unmanaged peers", and
//! after 5 failed reconciles the daemon fail-closes PERMANENTLY. The former
//! traversal-only fleet-wide refresh against an earlier narrowed assignment
//! state (live_two_hop's chain) permanently bricked daemons mid-run (run
//! linux-u11b-5node-negctl-relayfwd). The pair swap mirrors production's
//! single-env mint (`refresh_local_traversal_bundle_from_specs`): both kinds
//! from ONE ctx.assignments snapshot, installed atomically per node while
//! the daemon + refresh units are stopped, then health-gated before moving
//! on.
//!
//! This stage drives the exact same mint + distribute path the setup stages
//! use (`build_bundle_env` + the exit adapter + the verifier-key barrier),
//! so nodes receive freshly signed bundles with the configured (never
//! lengthened) TTL.
//!
//! Gated: only runs when relay-forwarding validation is elected for the run;
//! otherwise it is Skipped (fail-closed) so the default plan is unchanged.

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::{BundleKind, StageOutcome};
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::distribute_assignments::{
    TRAVERSAL_BUNDLE_FILE_EXT, TRAVERSAL_BUNDLE_FILE_PREFIX, build_bundle_env,
    distribute_bundle_kind_scoped,
};
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

pub struct RefreshSignedBundlesStage {
    max_parallel_node_workers: usize,
    shutdown_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl RefreshSignedBundlesStage {
    pub fn new(
        max_parallel_node_workers: usize,
        shutdown_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Self {
            max_parallel_node_workers: max_parallel_node_workers.max(1),
            shutdown_flag,
        }
    }
}

impl OrchestrationStage for RefreshSignedBundlesStage {
    fn id(&self) -> StageId {
        StageId::RefreshSignedBundles
    }
    fn name(&self) -> &str {
        "refresh_signed_bundles"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::DeployRelayService, StageId::RelayValidation]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        if !ctx.relay_forwarding_validation_elected {
            return StageOutcome::Skipped(
                "relay forwarding validation not enabled for this run".to_owned(),
            );
        }
        use crate::vm_lab::orchestrator::stage::distribute_assignments::{
            DNS_ZONE_BUNDLE_FILE_EXT, DNS_ZONE_BUNDLE_FILE_PREFIX,
            distribute_bundle_kind_for_refresh,
        };
        // HP-3 root-cause fix (run linux-u11b-5node-negctl-relayfwd): the
        // traversal bundle must NEVER be re-minted fleet-wide while the
        // daemons keep their OLD assignment bundles. The daemon enforces the
        // QH-04 pair invariant on BOTH directions: a traversal snapshot that
        // holds peers the node's own assignment does not manage is
        // "traversal authority snapshot contains unmanaged peers", and after
        // 5 failed reconciles the daemon fail-closes PERMANENTLY
        // (restricted_safe_mode=true). The former traversal-only refresh
        // minted a full-fleet snapshot against the (earlier, legitimately)
        // narrowed live_two_hop assignment state and permanently bricked
        // three daemons mid-run. Production never has this window: it mints
        // assignment+traversal from ONE env file
        // (`refresh_local_traversal_bundle_from_specs`). The lab harness now
        // mirrors that: per node, quiesce the daemon + refresh units, install
        // a matched assignment+traversal pair minted from the SAME
        // ctx.assignments snapshot, resume, and require a healthy status
        // before moving on.
        let pair = refresh_assignment_traversal_pair(
            ctx,
            self.max_parallel_node_workers,
            &self.shutdown_flag,
        );
        if let StageOutcome::Failed(_) = pair {
            return pair;
        }
        let dns_zone = distribute_bundle_kind_for_refresh(
            ctx,
            BundleKind::DnsZone,
            DNS_ZONE_BUNDLE_FILE_PREFIX,
            DNS_ZONE_BUNDLE_FILE_EXT,
            self.max_parallel_node_workers,
            &self.shutdown_flag,
        );
        if let StageOutcome::Failed(_) = dns_zone {
            return dns_zone;
        }
        // NOTE: no Skipped arm on dns_zone (or the pair) by design —
        // distribute_bundle_kind_for_refresh only ever returns Passed or Failed (a
        // missing exit node is Failed, never Skipped), so a Skipped outcome
        // here would be unreachable defensive code.
        pair
    }
}

/// Bounded post-swap health window per Linux node: the daemon must come back
/// reporting no restriction, no reconcile error, and a traversal peer count
/// exactly matching this run's assignment fan-in
/// (`assignments.len() - 1`), or the stage fails instead of handing HP-3 a
/// poisoned mesh.
const REFRESH_SWAP_HEALTH_TIMEOUT_SECS: u64 = 120;
const REFRESH_SWAP_HEALTH_POLL_INTERVAL_SECS: u64 = 3;
/// Machine-readable success witness for the pair swap (QH-83): per-node
/// digests of the exact assignment and traversal bundles that were installed
/// together. A Passed verdict whose witness write fails is Failed.
const REFRESH_PAIR_EVIDENCE_FILENAME: &str = "refresh_signed_bundles.pair_evidence.json";

/// Quiesce half of the [`BundleSwapFence`]-equivalent used by the two-hop
/// binary: stop the daemon AND the assignment-refresh timer/service so the
/// installs below are atomic from the daemon's point of view and no
/// reconcile failure is counted toward the Permanent fail-closed threshold.
///
/// The marker prints only when `systemctl stop` succeeded. A failed stop
/// leaves a daemon that can reconcile mid-install, which is the harm this
/// fence exists to prevent, so the caller must see it as a failure.
fn build_refresh_pair_quiesce_script() -> String {
    "sudo systemctl stop rustynetd.service rustynetd-assignment-refresh.timer rustynetd-assignment-refresh.service \
     && echo HP3_BUNDLE_SWAP_QUIESCED=1"
        .to_owned()
}

/// Resume half: the refresh timer FIRST (the production ordering), then the
/// daemon, then a short settle so the health poll below observes the daemon
/// after it has re-read its signed state.
///
/// Both starts are always attempted, so a failed timer start never leaves the
/// daemon stopped, and the marker prints only when both succeeded.
fn build_refresh_pair_resume_script() -> String {
    "sudo systemctl start rustynetd-assignment-refresh.timer; timer_rc=$?; \
     sudo systemctl start rustynetd.service; daemon_rc=$?; \
     sleep 3; \
     if [ \"$timer_rc\" -eq 0 ] && [ \"$daemon_rc\" -eq 0 ]; then echo HP3_BUNDLE_SWAP_RESUMED=1; fi"
        .to_owned()
}

/// Wire names for the two kinds in the pair. Traversal reuses the shared
/// minter constants (the naming-pin test forbids re-spelling it here);
/// assignment matches the setup stage's literal (`rn-assignment`/`assignment`).
fn assignment_bundle_file_name(node_id: &str) -> String {
    format!("rn-assignment-{node_id}.assignment")
}

fn traversal_bundle_file_name(node_id: &str) -> String {
    format!("{TRAVERSAL_BUNDLE_FILE_PREFIX}-{node_id}.{TRAVERSAL_BUNDLE_FILE_EXT}",)
}

/// Per-node success witness for the pair swap: the host-side digests of the
/// exact matched bundle files that were installed together while the daemon
/// was quiesced.
struct RefreshPairWitness {
    alias: String,
    node_id: String,
    assignment_sha256: String,
    traversal_sha256: String,
    /// Raw `rustynet status` line captured AFTER the pair install, resume
    /// and health gate. This is the timer-tick witness: the node-local
    /// refresh timer is re-armed by the resume script before this capture,
    /// so the recorded line shows the restriction/peer-count state the
    /// daemon settles into once ticks resume on the swapped pair
    /// (katana-xnet-169 shipped no post-refresh status at all).
    post_refresh_status: String,
}

/// Per-node, quiesced assignment+traversal PAIR swap. See the execute()
/// comment for why the traversal-only fleet-wide refresh was the HP-3 root
/// cause. Fail-closed: any per-node failure aborts the stage (later nodes
/// keep their setup-time bundles, which are self-consistent pairs).
fn refresh_assignment_traversal_pair(
    ctx: &mut OrchestrationContext,
    max_parallel_node_workers: usize,
    shutdown_flag: &std::sync::atomic::AtomicBool,
) -> StageOutcome {
    match refresh_assignment_traversal_pair_inner(ctx, max_parallel_node_workers, shutdown_flag) {
        Ok(()) => StageOutcome::Passed,
        Err(e) => StageOutcome::Failed(e),
    }
}

fn refresh_assignment_traversal_pair_inner(
    ctx: &mut OrchestrationContext,
    max_parallel_node_workers: usize,
    shutdown_flag: &std::sync::atomic::AtomicBool,
) -> Result<(), String> {
    let exit_alias = ctx
        .assignments
        .iter()
        .find(|a| a.role == NodeRole::Exit)
        .map(|a| a.alias.clone())
        .ok_or_else(|| "no Exit node in assignments".to_owned())?;
    // THE pair invariant: both bundles are minted from the SAME
    // ctx.assignments snapshot, so what the daemon is told to manage
    // (assignment) and what it is told peers hold (traversal) can never
    // disagree — the property the daemon's QH-04 check demands.
    let assignment_env =
        build_bundle_env(ctx, &BundleKind::Assignment).map_err(|e| format!("build env: {e}"))?;
    let traversal_env =
        build_bundle_env(ctx, &BundleKind::Traversal).map_err(|e| format!("build env: {e}"))?;
    let expected_managed_peers = ctx.assignments.len().saturating_sub(1) as u64;
    let inventory_path = ctx
        .inventory_path
        .clone()
        .ok_or_else(|| "orchestration context carries no inventory path".to_owned())?;

    let tmp_dir = {
        let mut p = std::env::temp_dir();
        p.push(format!("rn_bundle_pair_{}", std::process::id()));
        std::fs::create_dir_all(&p).map_err(|e| format!("create tmp bundle dir: {e}"))?;
        p
    };

    let witnesses: Result<Vec<RefreshPairWitness>, String> = (|| {
        // 1. Mint BOTH kinds once, through the exit adapter, into one dir.
        {
            let exit_adapter = ctx
                .adapters
                .get(exit_alias.as_str())
                .ok_or_else(|| format!("no adapter for exit '{exit_alias}'"))?;
            exit_adapter
                .issue_bundles_to_dir(BundleKind::Assignment, &assignment_env, &tmp_dir)
                .map_err(|e| format!("issue assignment bundles: {e}"))?;
            exit_adapter
                .issue_bundles_to_dir(BundleKind::Traversal, &traversal_env, &tmp_dir)
                .map_err(|e| format!("issue traversal bundles: {e}"))?;
        }
        // 2. Both verifier keys must be present and well-formed before any
        //    node is touched (same fail-closed shape as the setup barrier).
        for kind in [BundleKind::Assignment, BundleKind::Traversal] {
            let pub_key_path = tmp_dir.join(format!("rn-{kind}.pub"));
            crate::vm_lab::orchestrator::adapter::verifier_key::validated_verifier_key_sha256(
                &pub_key_path,
            )
            .map_err(|err| format!("issued {kind} verifier key invalid: {err}"))?;
        }

        // 3. Per-node facts resolved up front (a missing node_id/adapter is a
        //    stage failure, not a skip).
        let node_facts: Vec<(String, String, VmGuestPlatform)> = ctx
            .assignments
            .iter()
            .map(|a| {
                let node_id = ctx
                    .node_ids
                    .get(&a.alias)
                    .ok_or_else(|| format!("no node_id for '{}'", a.alias))?;
                let platform = ctx
                    .adapters
                    .get(&a.alias)
                    .map(|adapter| adapter.platform())
                    .ok_or_else(|| format!("no adapter registered for '{}'", a.alias))?;
                Ok((a.alias.clone(), node_id.clone(), platform))
            })
            .collect::<Result<Vec<_>, String>>()?;

        let mut witnesses = Vec::new();
        for (alias, node_id, platform) in &node_facts {
            if *platform != VmGuestPlatform::Linux {
                // Non-Linux nodes were never narrowed by the two-hop proof
                // (Linux-only) and their assignment stays the setup-time
                // full-mesh bundle: only traversal FRESHNESS is refreshed,
                // scoped to this node, never the pair.
                let outcome = distribute_bundle_kind_scoped(
                    ctx,
                    BundleKind::Traversal,
                    TRAVERSAL_BUNDLE_FILE_PREFIX,
                    TRAVERSAL_BUNDLE_FILE_EXT,
                    max_parallel_node_workers,
                    shutdown_flag,
                    alias,
                );
                if let StageOutcome::Failed(e) = outcome {
                    return Err(format!("{alias}: scoped traversal refresh: {e}"));
                }
                continue;
            }

            let (params, target) = {
                let adapter = ctx
                    .adapters
                    .get(alias.as_str())
                    .ok_or_else(|| format!("no adapter for '{alias}'"))?;
                let params = adapter.ssh_connection_params().ok_or_else(|| {
                    format!("{alias}: no SSH connection params for the pair swap")
                })?;
                let mut targets = crate::vm_lab::resolve_remote_targets(
                    std::path::Path::new(&inventory_path),
                    &[alias.clone()],
                    false,
                    &[],
                )
                .map_err(|e| format!("{alias}: resolve remote target: {e}"))?;
                let target = targets
                    .pop()
                    .ok_or_else(|| format!("{alias}: no resolved remote target"))?;
                (params, target)
            };

            // 3a. Quiesce: daemon + refresh timer/service stopped.
            let quiesce_out = crate::vm_lab::run_vm_lab_node_script(
                &target,
                &params.identity_file,
                Some(params.known_hosts.as_path()),
                build_refresh_pair_quiesce_script().as_str(),
                "pair swap: quiesce",
            )?;
            if !quiesce_out.contains("HP3_BUNDLE_SWAP_QUIESCED=1") {
                // Units may be half-stopped — always try to resume before
                // failing so the node is not left darker than we found it.
                let _ = crate::vm_lab::run_vm_lab_node_script(
                    &target,
                    &params.identity_file,
                    Some(params.known_hosts.as_path()),
                    build_refresh_pair_resume_script().as_str(),
                    "pair swap: resume (after failed quiesce)",
                );
                return Err(format!(
                    "{alias}: quiesce did not report success: {quiesce_out}"
                ));
            }

            // 3b. Install the matched pair: verifier then bundle, assignment
            //     then traversal — all while the daemon cannot reconcile.
            let install_result: Result<(), String> = (|| {
                for kind in [BundleKind::Assignment, BundleKind::Traversal] {
                    let adapter = ctx
                        .adapters
                        .get(alias.as_str())
                        .ok_or_else(|| format!("no adapter for '{alias}'"))?;
                    let pub_path = tmp_dir.join(format!("rn-{kind}.pub"));
                    adapter
                        .distribute_verifier_key(kind.clone(), &pub_path)
                        .map_err(|e| format!("{alias}: distribute {kind} verifier key: {e}"))?;
                    let fname = match kind {
                        BundleKind::Assignment => assignment_bundle_file_name(node_id),
                        BundleKind::Traversal => traversal_bundle_file_name(node_id),
                        BundleKind::DnsZone | BundleKind::Membership => {
                            unreachable!("only the assignment+traversal pair is swapped")
                        }
                    };
                    let bundle_path = tmp_dir.join(&fname);
                    if !bundle_path.exists() {
                        return Err(format!("{alias}: minted bundle not found: {fname}"));
                    }
                    adapter
                        .distribute_signed_bundle(kind.clone(), &bundle_path)
                        .map_err(|e| format!("{alias}: distribute {kind} bundle: {e}"))?;
                }
                Ok(())
            })();

            // 3c. ALWAYS resume, even when the install failed: a quiesced
            //     node must never be left stopped.
            let resume_out = crate::vm_lab::run_vm_lab_node_script(
                &target,
                &params.identity_file,
                Some(params.known_hosts.as_path()),
                build_refresh_pair_resume_script().as_str(),
                "pair swap: resume",
            )?;
            if !resume_out.contains("HP3_BUNDLE_SWAP_RESUMED=1") {
                return Err(format!(
                    "{alias}: resume did not report success: {resume_out}; install result: {install_result:?}"
                ));
            }
            install_result?;

            // 3d. Bounded health poll: the daemon must accept the pair.
            crate::vm_lab::wait_for_vm_lab_node_health(
                &target,
                &params.identity_file,
                Some(params.known_hosts.as_path()),
                expected_managed_peers,
                REFRESH_SWAP_HEALTH_TIMEOUT_SECS,
                REFRESH_SWAP_HEALTH_POLL_INTERVAL_SECS,
            )?;

            // 3e. Post-refresh status capture: the resume script above
            //     re-armed rustynetd-assignment-refresh.timer, so this line
            //     witnesses the state the daemon settles into once
            //     node-local refresh ticks resume on the swapped pair. It
            //     is captured AFTER the health gate on purpose: a capture
            //     taken before the resume would show the quiesced daemon
            //     and witness nothing about the tick behaviour. Strict: a
            //     witness this stage cannot collect is a stage failure,
            //     never an absent record.
            let post_refresh_status = crate::vm_lab::run_vm_lab_node_script(
                &target,
                &params.identity_file,
                Some(params.known_hosts.as_path()),
                crate::vm_lab::build_relay_forward_test_status_script().as_str(),
                "post-refresh node status capture",
            )
            .map_err(|e| format!("{alias}: post-refresh status capture failed: {e}"))?;

            // 3f. Witness the exact installed bytes.
            let assignment_path = tmp_dir.join(assignment_bundle_file_name(node_id));
            let traversal_path = tmp_dir.join(traversal_bundle_file_name(node_id));
            let assignment_sha256 =
                crate::vm_lab::orchestrator::adapter::verifier_key::sha256_hex_of_file(
                    &assignment_path,
                )
                .map_err(|e| format!("{alias}: assignment bundle digest: {e}"))?;
            let traversal_sha256 =
                crate::vm_lab::orchestrator::adapter::verifier_key::sha256_hex_of_file(
                    &traversal_path,
                )
                .map_err(|e| format!("{alias}: traversal bundle digest: {e}"))?;
            witnesses.push(RefreshPairWitness {
                alias: alias.clone(),
                node_id: node_id.clone(),
                assignment_sha256,
                traversal_sha256,
                post_refresh_status,
            });
        }
        Ok(witnesses)
    })();

    let _ = std::fs::remove_dir_all(&tmp_dir);
    let witnesses = witnesses?;

    // QH-83: the stage's declared evidence file is the Refresh-scoped
    // traversal bundle witness; the pair swap now owns writing it (for the
    // Linux nodes it installed directly — non-Linux nodes write their own
    // Scoped records above). A pass without this witness is demoted, so the
    // write is fatal.
    let traversal_entries: Vec<
        crate::vm_lab::orchestrator::stage::bundle_evidence::BundleWitnessEntry,
    > = witnesses
        .iter()
        .map(|w| {
            let platform = ctx
                .adapters
                .get(w.alias.as_str())
                .map(|adapter| adapter.platform())
                .ok_or_else(|| format!("no adapter for '{}'", w.alias))?;
            Ok(
                crate::vm_lab::orchestrator::stage::bundle_evidence::BundleWitnessEntry {
                    alias: w.alias.clone(),
                    node_id: w.node_id.clone(),
                    file: traversal_bundle_file_name(&w.node_id),
                    sha256: w.traversal_sha256.clone(),
                    install_dst: crate::vm_lab::orchestrator::stage::bundle_evidence::bundle_install_dst_for_platform(platform, &BundleKind::Traversal)?,
                },
            )
        })
        .collect::<Result<Vec<_>, String>>()?;
    crate::vm_lab::orchestrator::stage::bundle_evidence::write_bundle_evidence(
        &ctx.report_dir,
        &BundleKind::Traversal,
        crate::vm_lab::orchestrator::stage::bundle_evidence::BundleWitnessScope::Refresh,
        &traversal_entries,
    )
    .map_err(|e| format!("traversal bundle evidence write failed: {e}"))?;

    // Pair witness: assignment + traversal digests side by side per node —
    // the on-disk record that the two generations were swapped together —
    // plus the per-node post-refresh status capture.
    let body = refresh_pair_evidence_body(expected_managed_peers, &witnesses);
    let encoded = serde_json::to_vec_pretty(&body)
        .map_err(|e| format!("serializing pair evidence failed: {e}"))?;
    let path = ctx.report_dir.join(REFRESH_PAIR_EVIDENCE_FILENAME);
    std::fs::write(&path, encoded)
        .map_err(|e| format!("writing {REFRESH_PAIR_EVIDENCE_FILENAME} failed: {e}"))?;
    Ok(())
}

/// Builds the `refresh_signed_bundles.pair_evidence.json` body: the expected
/// managed-peer count, the assignment/traversal digest pair per node, and —
/// the timer-tick witness — each node's post-refresh raw `rustynet status`
/// line, keyed by alias. Extracted as a pure function so a test can assert
/// the CAPTURED status travels into the evidence verbatim.
fn refresh_pair_evidence_body(
    expected_managed_peers: u64,
    witnesses: &[RefreshPairWitness],
) -> serde_json::Value {
    serde_json::json!({
        "stage": "refresh_signed_bundles",
        "expected_managed_peers": expected_managed_peers,
        "pairs": witnesses
            .iter()
            .map(|w| {
                serde_json::json!({
                    "alias": w.alias,
                    "node_id": w.node_id,
                    "assignment_sha256": w.assignment_sha256,
                    "traversal_sha256": w.traversal_sha256,
                })
            })
            .collect::<Vec<_>>(),
        "post_refresh_status": witnesses
            .iter()
            .map(|w| {
                (
                    w.alias.clone(),
                    serde_json::Value::from(w.post_refresh_status.as_str()),
                )
            })
            .collect::<serde_json::Map<String, serde_json::Value>>(),
    })
}

#[cfg(test)]
mod bundle_naming_pins {
    //! Pins the naming agreement that made this stage fail the first time it
    //! ran live: the minter writes `<prefix>-<node_id>.<ext>` and the
    //! distributor looks the same name up, so every caller must spell both
    //! halves identically. This stage shipped with `"dns_zone"` against the
    //! setup stage's `"dns-zone"` and could not find a single bundle.
    use crate::vm_lab::orchestrator::stage::distribute_assignments::{
        DNS_ZONE_BUNDLE_FILE_EXT, DNS_ZONE_BUNDLE_FILE_PREFIX, TRAVERSAL_BUNDLE_FILE_EXT,
        TRAVERSAL_BUNDLE_FILE_PREFIX,
    };

    /// The extension is what the minter actually writes. `dns-zone` is the
    /// proven setup-stage spelling; an underscore here is the live failure.
    #[test]
    fn dns_zone_extension_is_the_minted_spelling() {
        assert_eq!(DNS_ZONE_BUNDLE_FILE_EXT, "dns-zone");
        assert_eq!(DNS_ZONE_BUNDLE_FILE_PREFIX, "rn-dns-zone");
        assert_eq!(TRAVERSAL_BUNDLE_FILE_EXT, "traversal");
        assert_eq!(TRAVERSAL_BUNDLE_FILE_PREFIX, "rn-traversal");
    }

    /// No caller of `distribute_bundle_kind` may re-spell the names inline —
    /// that is exactly how the two spellings diverged. Every stage that
    /// distributes a bundle must reference the shared constants.
    #[test]
    fn no_stage_spells_bundle_file_names_inline() {
        for (name, source) in [
            (
                "refresh_signed_bundles",
                crate::vm_lab::implementation_source_slice(include_str!(
                    "refresh_signed_bundles.rs"
                ))
                .expect("refresh_signed_bundles.rs implementation slice must parse"),
            ),
            (
                "distribute_dns_zone",
                crate::vm_lab::implementation_source_slice(include_str!("distribute_dns_zone.rs"))
                    .expect("distribute_dns_zone.rs implementation slice must parse"),
            ),
            (
                "distribute_traversal",
                crate::vm_lab::implementation_source_slice(include_str!("distribute_traversal.rs"))
                    .expect("distribute_traversal.rs implementation slice must parse"),
            ),
        ] {
            let production = source;
            for literal in [
                "\"dns-zone\"",
                "\"dns_zone\"",
                "\"rn-dns-zone\"",
                "\"rn-traversal\"",
            ] {
                assert!(
                    !production.contains(literal),
                    "{name} spells {literal} inline; use the shared constant so the \
                     minter and the lookup cannot drift"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::adapter::node_adapter::NodeAdapter;
    use crate::vm_lab::orchestrator::error::{
        AdapterError, GossipIdentity, InstallReport, MembershipOwnerKey, MembershipSnapshot,
        NodeId, NodeMembershipPeer, TrafficTestResult, TunnelsList, ValidatorReport,
        WireguardPublicKey,
    };
    use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
    use crate::vm_lab::orchestrator::source_archive::SourceArchive;
    use std::collections::HashMap;
    use std::path::Path;

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
            reflexive_endpoints: HashMap::new(),
            lab_stun_servers: Vec::new(),
            linux_backend: None,
            orchestrator_dialect: None,
            substrate: None,
            substrate_record: None,
            inventory_path: None,
            macos_anchor_validators_elected: false,
            macos_role_transition_elected: false,
            macos_reboot_recovery_elected: false,
            relay_forwarding_validation_elected: false,
        }
    }

    #[test]
    fn metadata_matches_catalog_entry() {
        let stage = RefreshSignedBundlesStage::new(
            1,
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        );
        assert_eq!(stage.id(), StageId::RefreshSignedBundles);
        assert_eq!(stage.name(), "refresh_signed_bundles");
        assert_eq!(
            stage.dependencies(),
            &[StageId::DeployRelayService, StageId::RelayValidation]
        );
        assert!(stage.applies_to_roles().is_empty());
        assert!(matches!(stage.fanout(), StageFanout::Once));
    }

    #[test]
    fn skips_when_relay_forwarding_validation_not_elected() {
        let mut ctx = empty_ctx();
        ctx.relay_forwarding_validation_elected = false;
        assert!(matches!(
            RefreshSignedBundlesStage::new(
                1,
                std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            )
            .execute(&mut ctx),
            StageOutcome::Skipped(_)
        ));
    }

    #[test]
    fn fail_closed_without_assignments_when_elected() {
        // With the election on but no assignments (no Exit node), the first
        // distribute call must Fail loudly rather than pass a skip downstream.
        let mut ctx = empty_ctx();
        ctx.relay_forwarding_validation_elected = true;
        assert!(matches!(
            RefreshSignedBundlesStage::new(
                1,
                std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            )
            .execute(&mut ctx),
            StageOutcome::Failed(_)
        ));
    }

    // ── HP-3 assignment+traversal pair swap ────────────────────────────

    /// Runs a pair-swap script under `/bin/sh` with `sudo`, `systemctl` and
    /// `sleep` replaced by stubs on PATH. The `systemctl` stub logs each call
    /// and exits `systemctl_rc`. Returns stdout and the logged calls.
    fn run_swap_script_with_stubs(script: &str, systemctl_rc: i32) -> (String, Vec<String>) {
        use std::os::unix::fs::PermissionsExt;
        let stub_dir = tempfile::tempdir().expect("stub dir should be created");
        let log = stub_dir.path().join("systemctl.log");
        for (name, body) in [
            ("sudo", "#!/bin/sh\nexec \"$@\"\n"),
            ("sleep", "#!/bin/sh\nexit 0\n"),
            (
                "systemctl",
                "#!/bin/sh\necho \"$*\" >> \"$STUB_SYSTEMCTL_LOG\"\nexit \"$STUB_SYSTEMCTL_RC\"\n",
            ),
        ] {
            let path = stub_dir.path().join(name);
            std::fs::write(&path, body).expect("stub should be written");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                .expect("stub should be executable");
        }
        let output = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", stub_dir.path().display()),
            )
            .env("STUB_SYSTEMCTL_LOG", &log)
            .env("STUB_SYSTEMCTL_RC", systemctl_rc.to_string())
            .output()
            .expect("script should run under /bin/sh");
        let calls = std::fs::read_to_string(&log)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect();
        (String::from_utf8_lossy(&output.stdout).into_owned(), calls)
    }

    // Review a66 F1: with `;` before the echo the markers printed even when
    // systemctl failed, so a failed quiesce let the pair install under a live
    // daemon. These run the real scripts, so a presence-only marker fails.
    #[test]
    fn pair_quiesce_reports_success_only_when_every_unit_stopped() {
        let script = super::build_refresh_pair_quiesce_script();
        let (out, calls) = run_swap_script_with_stubs(&script, 0);
        assert!(out.contains("HP3_BUNDLE_SWAP_QUIESCED=1"), "{out}");
        assert_eq!(
            calls,
            vec![
                "stop rustynetd.service rustynetd-assignment-refresh.timer rustynetd-assignment-refresh.service"
            ],
            "quiesce must stop the daemon AND both refresh units"
        );

        let (out, _) = run_swap_script_with_stubs(&script, 1);
        assert!(
            !out.contains("HP3_BUNDLE_SWAP_QUIESCED=1"),
            "a failed stop must not report a quiesced node: {out}"
        );
    }

    #[test]
    fn pair_resume_starts_timer_then_daemon_and_reports_only_full_success() {
        let script = super::build_refresh_pair_resume_script();
        let (out, calls) = run_swap_script_with_stubs(&script, 0);
        assert!(out.contains("HP3_BUNDLE_SWAP_RESUMED=1"), "{out}");
        assert_eq!(
            calls,
            vec![
                "start rustynetd-assignment-refresh.timer",
                "start rustynetd.service"
            ],
            "production ordering: refresh timer first, daemon second"
        );

        // A failed start must not report success, and the daemon start is
        // still attempted so a quiesced node is never left stopped.
        let (out, calls) = run_swap_script_with_stubs(&script, 1);
        assert!(
            !out.contains("HP3_BUNDLE_SWAP_RESUMED=1"),
            "a failed start must not report a resumed node: {out}"
        );
        assert_eq!(
            calls,
            vec![
                "start rustynetd-assignment-refresh.timer",
                "start rustynetd.service"
            ]
        );
    }

    #[test]
    fn pair_bundle_file_names_match_the_minter_shape() {
        assert_eq!(
            super::assignment_bundle_file_name("nid-1"),
            "rn-assignment-nid-1.assignment"
        );
        assert_eq!(
            super::traversal_bundle_file_name("nid-1"),
            format!("{TRAVERSAL_BUNDLE_FILE_PREFIX}-nid-1.{TRAVERSAL_BUNDLE_FILE_EXT}")
        );
    }

    #[test]
    fn pair_env_kinds_share_one_assignments_snapshot() {
        // The whole point of the pair swap: both bundle kinds are minted
        // from the SAME ctx.assignments, so the daemon is never told to
        // manage a set that its traversal snapshot disagrees with (QH-04).
        let ctx = pair_two_node_ctx();
        let assignment = build_bundle_env(&ctx, &BundleKind::Assignment).expect("assignment env");
        let traversal = build_bundle_env(&ctx, &BundleKind::Traversal).expect("traversal env");
        let line_of = |env: &str, key: &str| {
            env.lines()
                .find(|l| l.starts_with(key))
                .unwrap_or_else(|| panic!("{key} missing"))
                .to_owned()
        };
        assert_eq!(
            line_of(&assignment, "NODES_SPEC="),
            line_of(&traversal, "NODES_SPEC="),
            "pair kinds must share one NODES_SPEC snapshot"
        );
        assert_eq!(
            line_of(&assignment, "ALLOW_SPEC="),
            line_of(&traversal, "ALLOW_SPEC="),
            "pair kinds must share one ALLOW_SPEC snapshot"
        );
        assert!(assignment.contains("ASSIGNMENTS_SPEC="));
        assert!(!traversal.contains("ASSIGNMENTS_SPEC="));
    }

    #[test]
    fn pair_health_gate_witnesses_real_failclosed_residue() {
        // Witness line shape from the HP-3 run residue
        // (linux-u11b-5node-negctl-relayfwd): a daemon pushed to Permanent
        // fail-closed restriction by a traversal snapshot holding peers its
        // assignment does not manage. The pair-swap health gate MUST reject
        // this shape, and accept a healthy full-mesh status.
        let failed = "node_id=debian-headless-2-bootstrap state=FailClosed restricted_safe_mode=true bootstrap_error=\"reconcile failure threshold exceeded: 102\" traversal_peer_count=4 last_reconcile_error=\"traversal authority snapshot contains unmanaged peers\"";
        assert!(
            crate::vm_lab::rustynet_status_health(failed, 4).is_err(),
            "FailClosed residue must fail the pair-swap health gate"
        );
        let healthy = "node_id=x state=Active restricted_safe_mode=false traversal_peer_count=4 last_reconcile_error=none";
        assert!(crate::vm_lab::rustynet_status_health(healthy, 4).is_ok());
    }

    /// The pair evidence must carry the CAPTURED post-refresh status per
    /// node, verbatim: a fail-closed tick after the resume (exactly the
    /// katana-xnet-169 shape) must land in the evidence as
    /// restricted_safe_mode=true with the reconcile error, not be replaced
    /// by a summary or a hardcoded healthy line.
    #[test]
    fn refresh_pair_evidence_body_carries_post_refresh_status_per_node() {
        let poisoned = "node_id=katana-client-1-bootstrap state=FailClosed \
             restricted_safe_mode=true traversal_peer_count=1 \
             last_reconcile_error=\"traversal authority is missing signed traversal \
             state for managed peer katana-entry-1-bootstrap\"";
        let witnesses = vec![
            super::RefreshPairWitness {
                alias: "katana-client-1".to_owned(),
                node_id: "client-node-id".to_owned(),
                assignment_sha256: "a".repeat(64),
                traversal_sha256: "b".repeat(64),
                post_refresh_status: poisoned.to_owned(),
            },
            super::RefreshPairWitness {
                alias: "katana-entry-1".to_owned(),
                node_id: "entry-node-id".to_owned(),
                assignment_sha256: "c".repeat(64),
                traversal_sha256: "d".repeat(64),
                post_refresh_status: "node_id=entry state=Active restricted_safe_mode=false \
                 traversal_peer_count=3 last_reconcile_error=none"
                    .to_owned(),
            },
        ];
        let body = super::refresh_pair_evidence_body(3, &witnesses);
        assert_eq!(body["expected_managed_peers"], 3);
        assert_eq!(body["pairs"].as_array().map(Vec::len), Some(2));
        let client_status = body["post_refresh_status"]["katana-client-1"]
            .as_str()
            .expect("post_refresh_status must be keyed by alias");
        assert!(
            client_status.contains("restricted_safe_mode=true")
                && client_status.contains("traversal authority is missing signed traversal state"),
            "the captured poisoned line must travel verbatim: {client_status}"
        );
        let entry_status = body["post_refresh_status"]["katana-entry-1"]
            .as_str()
            .expect("post_refresh_status must be keyed by alias");
        assert!(
            entry_status.contains("restricted_safe_mode=false"),
            "{entry_status}"
        );
        assert!(
            !poisoned.contains("restricted_safe_mode=false"),
            "test self-check: the poisoned fixture must stay poisoned"
        );
    }

    /// The status capture is the TIMER-TICK witness only if it happens after
    /// the resume (timer re-armed) and after the health gate: a capture
    /// taken earlier shows the quiesced daemon and witnesses nothing. Source
    /// ordering inside the pair-swap body is the fail-loud pin.
    #[test]
    fn post_refresh_status_capture_follows_resume_and_health_gate() {
        let source =
            crate::vm_lab::implementation_source_slice(include_str!("refresh_signed_bundles.rs"))
                .expect("refresh_signed_bundles.rs implementation slice must parse");
        let fn_start = source
            .find("fn refresh_assignment_traversal_pair_inner(")
            .expect("pair swap body must exist");
        let fn_body = &source[fn_start..];
        let resume = fn_body
            .find("build_refresh_pair_resume_script()")
            .expect("resume script call must exist");
        let health = fn_body
            .find("wait_for_vm_lab_node_health(")
            .expect("health gate call must exist");
        let capture = fn_body
            .find("\"post-refresh node status capture\"")
            .expect("post-refresh capture must exist");
        assert!(
            resume < health && health < capture,
            "capture must follow resume ({resume}) and the health gate ({health}); found at {capture}"
        );
    }

    #[derive(Debug)]
    struct PairEnvAdapter {
        alias: &'static str,
        platform: VmGuestPlatform,
    }

    impl NodeAdapter for PairEnvAdapter {
        fn platform(&self) -> VmGuestPlatform {
            self.platform
        }
        fn alias(&self) -> &str {
            self.alias
        }
        fn collect_artifacts(&self, _dst: &Path) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn start_daemon(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn stop_daemon(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn restart_daemon(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn uninstall_daemon(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn issue_membership_owner_key(&self) -> Result<MembershipOwnerKey, AdapterError> {
            unimplemented!()
        }
        fn collect_wireguard_public_key(&self) -> Result<WireguardPublicKey, AdapterError> {
            unimplemented!()
        }
        fn collect_gossip_identity(&self) -> Result<GossipIdentity, AdapterError> {
            unimplemented!()
        }
        fn collect_node_id(&self) -> Result<NodeId, AdapterError> {
            unimplemented!()
        }
        fn run_validator(
            &self,
            _op: crate::vm_lab::DaemonProbeOp,
            _extra_args: &[String],
        ) -> Result<ValidatorReport, AdapterError> {
            unimplemented!()
        }
        fn ping_mesh_peer(&self, _peer_mesh_ip: &str) -> Result<TrafficTestResult, AdapterError> {
            unimplemented!()
        }
        fn probe_denied_peer(&self, _denied_ip: &str) -> Result<TrafficTestResult, AdapterError> {
            unimplemented!()
        }
        fn collect_active_tunnels(&self) -> Result<TunnelsList, AdapterError> {
            unimplemented!()
        }
        fn cleanup_runtime_state(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn check_ssh_reachable(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn endpoint(&self) -> String {
            unimplemented!()
        }
        fn collect_mesh_ip(&self) -> Result<String, AdapterError> {
            unimplemented!()
        }
        fn install_daemon(
            &self,
            _source: &SourceArchive,
            _ctx: &OrchestrationContext,
        ) -> Result<InstallReport, AdapterError> {
            unimplemented!()
        }
        fn init_membership_snapshot(
            &self,
            _owner_key: &MembershipOwnerKey,
            _peers: &[NodeMembershipPeer],
        ) -> Result<MembershipSnapshot, AdapterError> {
            unimplemented!()
        }
        fn distribute_signed_bundle(
            &self,
            _kind: BundleKind,
            _bundle_path: &Path,
        ) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn distribute_verifier_key(
            &self,
            _kind: BundleKind,
            _pub_key_path: &Path,
        ) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn issue_bundles_to_dir(
            &self,
            _kind: BundleKind,
            _env_content: &str,
            _local_out_dir: &Path,
        ) -> Result<(), AdapterError> {
            unimplemented!()
        }
    }

    fn pair_two_node_ctx() -> OrchestrationContext {
        let mut ctx = empty_ctx();
        ctx.assignments = vec![
            NodeRoleAssignment {
                alias: "exit-1".to_owned(),
                role: NodeRole::Exit,
            },
            NodeRoleAssignment {
                alias: "client-1".to_owned(),
                role: NodeRole::Client,
            },
        ];
        ctx.node_ids
            .insert("exit-1".to_owned(), "exit-node-id-abc".to_owned());
        ctx.node_ids
            .insert("client-1".to_owned(), "client-node-id-xyz".to_owned());
        ctx.collected_pubkeys
            .insert("exit-1".to_owned(), WireguardPublicKey("a".repeat(64)));
        ctx.collected_pubkeys
            .insert("client-1".to_owned(), WireguardPublicKey("b".repeat(64)));
        ctx.endpoints
            .insert("exit-1".to_owned(), "10.0.0.1:51820".to_owned());
        ctx.endpoints
            .insert("client-1".to_owned(), "10.0.0.2:51820".to_owned());
        ctx.adapters.insert(
            "exit-1".to_owned(),
            Box::new(PairEnvAdapter {
                alias: "exit-1",
                platform: VmGuestPlatform::Linux,
            }),
        );
        ctx.adapters.insert(
            "client-1".to_owned(),
            Box::new(PairEnvAdapter {
                alias: "client-1",
                platform: VmGuestPlatform::Linux,
            }),
        );
        ctx
    }
}
