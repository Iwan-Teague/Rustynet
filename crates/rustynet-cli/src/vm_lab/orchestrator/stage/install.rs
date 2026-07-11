#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

/// Pure predicate: is `alias` part of this run's active build set?
///
/// `None` (no `--rebuild-nodes`) means every node is active — the default.
/// `Some` limits the active set to the listed aliases. A node NOT in the active
/// set is **left entirely intact**: both `cleanup_hosts` and `bootstrap_hosts`
/// skip it, so it keeps its already-installed, already-running daemon from a
/// prior run. (The two stages must agree — `cleanup_hosts` wipes runtime state,
/// so cleaning a node we then refuse to rebuild would strand it without a
/// daemon.) This lets a single-node daemon fix be retested without a full
/// multi-node rebuild.
pub fn node_in_rebuild_set(rebuild_only: Option<&[String]>, alias: &str) -> bool {
    match rebuild_only {
        None => true,
        Some(list) => list.iter().any(|a| a == alias),
    }
}

pub struct BootstrapHostsStage {
    /// When `Some`, only these aliases are (re)built; others reuse their
    /// existing daemon. `None` = rebuild every node (the default).
    rebuild_only: Option<Vec<String>>,
    max_parallel_node_workers: usize,
    shutdown_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl BootstrapHostsStage {
    pub fn new(
        rebuild_only: Option<Vec<String>>,
        max_parallel_node_workers: usize,
        shutdown_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        BootstrapHostsStage {
            rebuild_only,
            max_parallel_node_workers: max_parallel_node_workers.max(1),
            shutdown_flag,
        }
    }
}

impl OrchestrationStage for BootstrapHostsStage {
    fn id(&self) -> StageId {
        StageId::BootstrapHosts
    }
    fn name(&self) -> &str {
        "bootstrap_hosts"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::CleanupHosts]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::PerNode
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let source = match ctx.source_archive.clone() {
            Some(s) => s,
            None => return StageOutcome::Failed("no source archive in context".to_owned()),
        };
        let rebuild_only = self.rebuild_only.as_deref();
        let aliases: Vec<String> = ctx.assignments.iter().map(|a| a.alias.clone()).collect();
        let results = crate::vm_lab::orchestrator::parallel::bounded_parallel_map_cancellable(
            &aliases,
            self.max_parallel_node_workers,
            &self.shutdown_flag,
            |alias| {
                if !node_in_rebuild_set(rebuild_only, alias) {
                    // Not in --rebuild-nodes: leave the node intact (cleanup_hosts
                    // skipped it too), reusing its existing daemon build.
                    // Downstream stages re-collect this node's identity from the
                    // live host over SSH, so no rebuild is required.
                    let r = match ctx.adapters.get(alias.as_str()) {
                        Some(adapter) => validate_reused_daemon(alias, adapter.as_ref()),
                        None => Err(format!(
                            "no adapter for reused node '{alias}'; cannot validate daemon readiness"
                        )),
                    };
                    return (alias.clone(), r);
                }
                let r = match ctx.adapters.get(alias.as_str()) {
                    Some(adapter) => adapter
                        .install_daemon(&source, ctx)
                        .map(|_| ())
                        .map_err(|e| e.to_string()),
                    None => Err(format!("no adapter for '{alias}'")),
                };
                (alias.clone(), r)
            },
            |alias| {
                (
                    alias.clone(),
                    Err("cancelled before node work was admitted".to_owned()),
                )
            },
        );
        let errors: Vec<String> = results
            .into_iter()
            .filter_map(|(alias, r)| r.err().map(|e| format!("{alias}: {e}")))
            .collect();
        if errors.is_empty() {
            StageOutcome::Passed
        } else {
            StageOutcome::Failed(errors.join("; "))
        }
    }
}

fn validate_reused_daemon(
    alias: &str,
    adapter: &dyn crate::vm_lab::orchestrator::adapter::node_adapter::NodeAdapter,
) -> Result<(), String> {
    adapter.collect_node_id().map_err(|err| {
        format!(
            "reused node excluded by --rebuild-nodes is not daemon-ready \
             (node_id probe failed); include '{alias}' in --rebuild-nodes or run without \
             --rebuild-nodes to rebuild all nodes: {err}"
        )
    })?;
    adapter.collect_wireguard_public_key().map_err(|err| {
        format!(
            "reused node excluded by --rebuild-nodes is not daemon-ready \
             (wireguard public-key probe failed); include '{alias}' in --rebuild-nodes or run \
             without --rebuild-nodes to rebuild all nodes: {err}"
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
    use crate::vm_lab::orchestrator::source_archive::SourceArchive;
    use std::collections::HashMap;

    fn ctx_with_assignment(alias: &str) -> OrchestrationContext {
        OrchestrationContext {
            assignments: vec![NodeRoleAssignment {
                alias: alias.to_owned(),
                role: NodeRole::Client,
            }],
            adapters: HashMap::new(),
            source_archive: Some(SourceArchive {
                path: std::env::temp_dir(),
            }),
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
    fn no_source_archive_fails() {
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
            orchestrator_dialect: None,
        };
        assert!(matches!(
            BootstrapHostsStage::new(
                None,
                1,
                std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            )
            .execute(&mut ctx),
            StageOutcome::Failed(_)
        ));
    }

    #[test]
    fn node_in_rebuild_set_none_includes_all() {
        // Default (no --rebuild-nodes): every node rebuilds.
        assert!(node_in_rebuild_set(None, "windows-utm-1"));
        assert!(node_in_rebuild_set(None, "debian-headless-1"));
    }

    #[test]
    fn node_in_rebuild_set_some_limits_to_listed() {
        let only = vec!["windows-utm-1".to_owned()];
        assert!(node_in_rebuild_set(Some(&only), "windows-utm-1"));
        assert!(!node_in_rebuild_set(Some(&only), "debian-headless-1"));
    }

    #[test]
    fn node_in_rebuild_set_empty_list_includes_nothing() {
        // An explicit empty set rebuilds no node (every node is reused as-is).
        let none: Vec<String> = vec![];
        assert!(!node_in_rebuild_set(Some(&none), "windows-utm-1"));
    }

    #[test]
    fn reused_node_without_adapter_fails_at_bootstrap_gate() {
        let mut ctx = ctx_with_assignment("reused-node");
        let stage = BootstrapHostsStage::new(
            Some(vec!["other-node".to_owned()]),
            1,
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        );
        let outcome = stage.execute(&mut ctx);
        assert!(matches!(outcome, StageOutcome::Failed(_)));
        let StageOutcome::Failed(message) = outcome else {
            unreachable!("checked above");
        };
        assert!(message.contains("cannot validate daemon readiness"));
    }
}
