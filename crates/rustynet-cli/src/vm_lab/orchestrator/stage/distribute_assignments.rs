#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::{BundleKind, StageOutcome};
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

pub struct DistributeAssignmentsStage;

impl OrchestrationStage for DistributeAssignmentsStage {
    fn id(&self) -> StageId {
        StageId::DistributeAssignments
    }
    fn name(&self) -> &str {
        "distribute_assignments"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::DistributeMembership]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        distribute_bundle_kind(ctx, BundleKind::Assignment, "rn-assignment", "assignment")
    }
}

/// Build the env file content for bundle issuance.
pub(crate) fn build_bundle_env(
    ctx: &OrchestrationContext,
    kind: &BundleKind,
) -> Result<String, String> {
    // NODES_SPEC: node_id|endpoint|public_key_hex;...
    let mut nodes_parts = Vec::new();
    for a in &ctx.assignments {
        let node_id = ctx
            .node_ids
            .get(&a.alias)
            .ok_or_else(|| format!("no node_id for '{}'", a.alias))?;
        let pubkey = ctx
            .collected_pubkeys
            .get(&a.alias)
            .ok_or_else(|| format!("no pubkey for '{}'", a.alias))?;
        let endpoint = ctx
            .endpoints
            .get(&a.alias)
            .cloned()
            .unwrap_or_else(|| "0.0.0.0:51820".to_owned());
        nodes_parts.push(format!("{node_id}|{endpoint}|{}", pubkey.0));
    }
    let nodes_spec = nodes_parts.join(";");

    // ALLOW_SPEC: full mesh (every pair bidirectionally)
    let mut allow_parts = Vec::new();
    for src in &ctx.assignments {
        let src_id = ctx
            .node_ids
            .get(&src.alias)
            .ok_or_else(|| format!("no node_id for '{}'", src.alias))?;
        for dst in &ctx.assignments {
            if dst.alias == src.alias {
                continue;
            }
            let dst_id = ctx
                .node_ids
                .get(&dst.alias)
                .ok_or_else(|| format!("no node_id for '{}'", dst.alias))?;
            allow_parts.push(format!("{src_id}|{dst_id}"));
        }
    }
    let allow_spec = allow_parts.join(";");

    let mut lines = vec![
        format!("NODES_SPEC={nodes_spec}"),
        format!("ALLOW_SPEC={allow_spec}"),
    ];

    if matches!(kind, BundleKind::Traversal) {
        // Lab pipeline: use a 24-hour TTL so the traversal bundle remains valid through
        // the full pipeline and the reconcile loop.  Production nodes receive fresh
        // traversal bundles from the assignment-refresh timer; the lab distributes once.
        lines.push("TRAVERSAL_TTL_SECS=86400".to_owned());
    }

    if matches!(kind, BundleKind::Assignment) {
        // Lab pipeline: use a 24-hour TTL so the bundle remains valid through
        // enforce_baseline_runtime even when the pipeline takes several minutes.
        // Production nodes refresh assignments via the assignment-refresh timer and
        // never rely on a single long-lived bundle.
        lines.push("BUNDLE_TTL_SECS=86400".to_owned());
        let exit_node_id = ctx
            .assignments
            .iter()
            .find(|a| a.role == NodeRole::Exit)
            .and_then(|a| ctx.node_ids.get(&a.alias))
            .ok_or_else(|| "no exit node_id".to_owned())?
            .clone();
        let assignment_parts: Vec<String> = ctx
            .assignments
            .iter()
            .map(|a| {
                ctx.node_ids
                    .get(&a.alias)
                    .map(|nid| {
                        // The exit node itself gets `-` (no exit assignment);
                        // client nodes get assigned to the exit node.
                        let exit_part = if a.role == NodeRole::Exit {
                            "-"
                        } else {
                            exit_node_id.as_str()
                        };
                        format!("{nid}|{exit_part}")
                    })
                    .ok_or_else(|| format!("no node_id for '{}'", a.alias))
            })
            .collect::<Result<Vec<_>, _>>()?;
        lines.push(format!("ASSIGNMENTS_SPEC={}", assignment_parts.join(";")));
    }

    Ok(lines.join("\n") + "\n")
}

/// Shared bundle distribution logic used by Assignment, Traversal, and DnsZone stages.
pub(crate) fn distribute_bundle_kind(
    ctx: &mut OrchestrationContext,
    kind: BundleKind,
    file_prefix: &str,
    file_ext: &str,
) -> StageOutcome {
    let exit_alias = match ctx.assignments.iter().find(|a| a.role == NodeRole::Exit) {
        Some(a) => a.alias.clone(),
        None => return StageOutcome::Failed("no Exit node in assignments".to_owned()),
    };

    let env_content = match build_bundle_env(ctx, &kind) {
        Ok(c) => c,
        Err(e) => return StageOutcome::Failed(format!("build env: {e}")),
    };

    let tmp_dir = {
        let mut p = std::env::temp_dir();
        p.push(format!("rn_bundles_{}_{}", std::process::id(), kind));
        if let Err(e) = std::fs::create_dir_all(&p) {
            return StageOutcome::Failed(format!("create tmp bundle dir: {e}"));
        }
        p
    };

    // Issue bundles (exit adapter only — no ctx mutation needed after)
    {
        let exit_adapter = match ctx.adapters.get(exit_alias.as_str()) {
            Some(a) => a,
            None => {
                let _ = std::fs::remove_dir_all(&tmp_dir);
                return StageOutcome::Failed(format!("no adapter for exit '{exit_alias}'"));
            }
        };
        if let Err(e) = exit_adapter.issue_bundles_to_dir(kind.clone(), &env_content, &tmp_dir) {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return StageOutcome::Failed(format!("issue {kind} bundles: {e}"));
        }
    }

    // Collect alias→node_id mapping (no mutation)
    let aliases: Vec<(String, String)> = ctx
        .assignments
        .iter()
        .filter_map(|a| {
            ctx.node_ids
                .get(&a.alias)
                .map(|nid| (a.alias.clone(), nid.clone()))
        })
        .collect();

    // Distribute to each node
    let results: Vec<(String, Result<(), String>)> = aliases
        .iter()
        .map(|(alias, node_id)| {
            let fname = format!("{file_prefix}-{node_id}.{file_ext}");
            let bundle_path = tmp_dir.join(&fname);
            let r = if !bundle_path.exists() {
                Err(format!("bundle not found: {fname}"))
            } else {
                match ctx.adapters.get(alias.as_str()) {
                    Some(adapter) => adapter
                        .distribute_signed_bundle(kind.clone(), &bundle_path)
                        .map_err(|e| e.to_string()),
                    None => Err(format!("no adapter for '{alias}'")),
                }
            };
            (alias.clone(), r)
        })
        .collect();

    // Distribute verifier public key to all nodes (enables daemon to verify
    // freshly-distributed bundles).  The issuance step writes `rn-{kind}.pub`
    // to tmp_dir alongside the per-node bundle files.
    let pub_key_path = tmp_dir.join(format!("rn-{kind}.pub"));
    let verifier_results: Vec<(String, Result<(), String>)> = if pub_key_path.exists() {
        aliases
            .iter()
            .map(|(alias, _)| {
                let r = match ctx.adapters.get(alias.as_str()) {
                    Some(adapter) => adapter
                        .distribute_verifier_key(kind.clone(), &pub_key_path)
                        .map_err(|e| e.to_string()),
                    None => Err(format!("no adapter for '{alias}'")),
                };
                (alias.clone(), r)
            })
            .collect()
    } else {
        Vec::new()
    };

    let _ = std::fs::remove_dir_all(&tmp_dir);

    let mut errors: Vec<String> = results
        .into_iter()
        .filter_map(|(alias, r): (String, Result<(), String>)| {
            r.err().map(|e| format!("{alias}: {e}"))
        })
        .collect();
    errors.extend(verifier_results.into_iter().filter_map(
        |(alias, r): (String, Result<(), String>)| {
            r.err()
                .map(|e| format!("{alias}: distribute verifier key: {e}"))
        },
    ));
    if errors.is_empty() {
        StageOutcome::Passed
    } else {
        StageOutcome::Failed(errors.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::error::WireguardPublicKey;
    use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
    use std::collections::HashMap;

    fn make_two_node_ctx() -> OrchestrationContext {
        let mut ctx = OrchestrationContext {
            assignments: vec![
                NodeRoleAssignment {
                    alias: "exit-1".to_owned(),
                    role: NodeRole::Exit,
                },
                NodeRoleAssignment {
                    alias: "client-1".to_owned(),
                    role: NodeRole::Client,
                },
            ],
            adapters: HashMap::new(),
            source_archive: None,
            report_dir: std::env::temp_dir(),
            stage_outcomes: HashMap::new(),
            collected_pubkeys: HashMap::new(),
            network_id: "net".to_owned(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: Some(vec![1, 2, 3]),
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
        };
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
        ctx
    }

    #[test]
    fn build_bundle_env_produces_correct_keys() {
        let ctx = make_two_node_ctx();
        let env = build_bundle_env(&ctx, &BundleKind::Assignment).unwrap();
        assert!(env.contains("NODES_SPEC="), "must have NODES_SPEC");
        assert!(env.contains("ALLOW_SPEC="), "must have ALLOW_SPEC");
        assert!(
            env.contains("ASSIGNMENTS_SPEC="),
            "must have ASSIGNMENTS_SPEC"
        );
        assert!(
            env.contains("exit-node-id-abc"),
            "must contain exit node id"
        );
        assert!(
            env.contains("client-node-id-xyz"),
            "must contain client node id"
        );
    }

    #[test]
    fn build_bundle_env_traversal_has_no_assignments_spec() {
        let ctx = make_two_node_ctx();
        let env = build_bundle_env(&ctx, &BundleKind::Traversal).unwrap();
        assert!(
            !env.contains("ASSIGNMENTS_SPEC"),
            "traversal env must not have ASSIGNMENTS_SPEC"
        );
    }

    #[test]
    fn no_exit_node_fails() {
        let mut ctx = OrchestrationContext {
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
        };
        assert!(matches!(
            DistributeAssignmentsStage.execute(&mut ctx),
            StageOutcome::Failed(_)
        ));
    }
}
